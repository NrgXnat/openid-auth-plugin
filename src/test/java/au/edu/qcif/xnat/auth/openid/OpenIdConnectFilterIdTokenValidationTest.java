package au.edu.qcif.xnat.auth.openid;

import au.edu.qcif.xnat.auth.openid.jwt.JwtValidationException;
import au.edu.qcif.xnat.auth.openid.service.KeystoreService;
import com.github.tomakehurst.wiremock.junit.WireMockRule;
import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.RSAEncrypter;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;
import org.nrg.xdat.preferences.SiteConfigPreferences;
import org.nrg.xdat.services.XdatUserAuthService;
import org.springframework.security.authentication.AuthenticationEventPublisher;

import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.stubFor;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static com.github.tomakehurst.wiremock.core.WireMockConfiguration.options;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.when;

@RunWith(MockitoJUnitRunner.class)
public class OpenIdConnectFilterIdTokenValidationTest {

    private static final String PROVIDER = "keycloak";
    private static final String ISSUER = "https://idp.example/realms/xnat";

    @Rule
    public final WireMockRule wireMock = new WireMockRule(options().dynamicPort());

    @Mock private OpenIdAuthPlugin             plugin;
    @Mock private AuthenticationEventPublisher eventPublisher;
    @Mock private XdatUserAuthService          userAuthService;
    @Mock private SiteConfigPreferences        siteConfigPreferences;
    @Mock private KeystoreService              keystoreService;

    private static RSAKey signingKey;
    private static RSAKey strangerKey;
    private static RSAKey encryptionKey;

    @BeforeClass
    public static void generateKeys() throws Exception {
        signingKey = new RSAKeyGenerator(2048).keyID("k1").generate();
        strangerKey = new RSAKeyGenerator(2048).keyID("k2").generate();
        encryptionKey = new RSAKeyGenerator(2048).generate();
    }

    @Before
    public void serveJwks() {
        stubFor(get(urlEqualTo("/jwks")).willReturn(aResponse()
                .withStatus(200)
                .withHeader("Content-Type", "application/json")
                .withBody(new JWKSet(signingKey.toPublicJWK()).toString())));
    }

    private OpenIdConnectFilter filterWith(final Map<String, String> providerProps) {
        lenient().when(plugin.getRedirectUri()).thenReturn("/openid/callback");
        lenient().when(plugin.getEnabledProviders()).thenReturn(Collections.singletonList(PROVIDER));
        providerProps.forEach((key, value) -> lenient().when(plugin.getProperty(PROVIDER, key)).thenReturn(value));
        return new OpenIdConnectFilter(plugin, eventPublisher, userAuthService, siteConfigPreferences, keystoreService, Runnable::run);
    }

    private Map<String, String> issuerAndJwksUri() {
        final Map<String, String> props = new HashMap<>();
        props.put("issuer", ISSUER);
        props.put("jwksUri", "http://localhost:" + wireMock.port() + "/jwks");
        return props;
    }

    private static String signedIdToken(final RSAKey key) throws Exception {
        final JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .issuer(ISSUER)
                .subject("alice")
                .expirationTime(new Date(System.currentTimeMillis() + 3_600_000))
                .build();
        final SignedJWT jwt = new SignedJWT(
                new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(key.getKeyID()).build(), claims);
        jwt.sign(new RSASSASigner(key));
        return jwt.serialize();
    }

    private static String encrypted(final String signedIdToken) throws Exception {
        final JWEObject jwe = new JWEObject(
                new JWEHeader.Builder(JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A256GCM).contentType("JWT").build(),
                new Payload(signedIdToken));
        jwe.encrypt(new RSAEncrypter(encryptionKey.toRSAPublicKey()));
        return jwe.serialize();
    }

    private static void assertRejected(final OpenIdConnectFilter filter, final String idToken) throws Exception {
        try {
            filter.parseIdToken(idToken, PROVIDER);
            fail("expected JwtValidationException");
        } catch (JwtValidationException expected) {
            // pass
        }
    }

    private static void assertAccepted(final OpenIdConnectFilter filter, final String idToken) throws Exception {
        assertEquals("alice", filter.parseIdToken(idToken, PROVIDER).claims().getSubject());
    }

    @Test
    public void validatesByDefaultWhenIssuerAndJwksUriAreSet() throws Exception {
        final OpenIdConnectFilter filter = filterWith(issuerAndJwksUri());

        assertAccepted(filter, signedIdToken(signingKey));
        assertRejected(filter, signedIdToken(strangerKey));
    }

    @Test
    public void skipsValidationWhenDisabled() throws Exception {
        final Map<String, String> props = issuerAndJwksUri();
        props.put("idToken.validate.enabled", "false");

        assertAccepted(filterWith(props), signedIdToken(strangerKey));
    }

    @Test
    public void skipsValidationWithoutIssuerAndJwksUri() throws Exception {
        final OpenIdConnectFilter filter = filterWith(Collections.singletonMap("idToken.validate.enabled", "true"));

        assertAccepted(filter, signedIdToken(strangerKey));
    }

    @Test
    public void validatesTheSignedTokenInsideAnEncryptedIdToken() throws Exception {
        when(keystoreService.getEncryptionPrivateKey(PROVIDER)).thenReturn(encryptionKey.toPrivateKey());
        final OpenIdConnectFilter filter = filterWith(issuerAndJwksUri());

        assertAccepted(filter, encrypted(signedIdToken(signingKey)));
        assertRejected(filter, encrypted(signedIdToken(strangerKey)));
    }
}

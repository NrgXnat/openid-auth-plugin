package au.edu.qcif.xnat.auth.openid;

import au.edu.qcif.xnat.auth.openid.jwt.JwtValidationException;
import au.edu.qcif.xnat.auth.openid.jwt.JwtValidatorRegistry;
import au.edu.qcif.xnat.auth.openid.service.KeystoreService;
import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
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
import org.junit.After;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;
import org.nrg.xdat.preferences.SiteConfigPreferences;
import org.nrg.xdat.services.XdatUserAuthService;
import org.slf4j.LoggerFactory;
import org.springframework.context.event.ContextRefreshedEvent;
import org.springframework.security.authentication.AuthenticationEventPublisher;

import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.stubFor;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static com.github.tomakehurst.wiremock.core.WireMockConfiguration.options;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
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

    private ListAppender<ILoggingEvent> appender;
    private Logger                      logger;
    private Level                       originalLevel;

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

    @Before
    public void captureFilterLogging() {
        logger = (Logger) LoggerFactory.getLogger(OpenIdConnectFilter.class);
        originalLevel = logger.getLevel();
        logger.setLevel(Level.WARN);
        appender = new ListAppender<>();
        appender.start();
        logger.addAppender(appender);
    }

    @After
    public void restoreLogging() {
        logger.detachAppender(appender);
        logger.setLevel(originalLevel);
    }

    private List<String> startupWarnings(final OpenIdConnectFilter filter) {
        filter.onApplicationEvent(mock(ContextRefreshedEvent.class));
        return appender.list.stream()
                            .filter(event -> event.getLevel().equals(Level.WARN))
                            .map(ILoggingEvent::getFormattedMessage)
                            .collect(Collectors.toList());
    }

    private OpenIdConnectFilter filterWith(final Map<String, String> providerProps) {
        lenient().when(plugin.getRedirectUri()).thenReturn("/openid/callback");
        lenient().when(plugin.getEnabledProviders()).thenReturn(Collections.singletonList(PROVIDER));
        providerProps.forEach((key, value) -> lenient().when(plugin.getProperty(PROVIDER, key)).thenReturn(value));
        return new OpenIdConnectFilter(plugin, eventPublisher, userAuthService, siteConfigPreferences, keystoreService,
                new JwtValidatorRegistry(plugin), Runnable::run);
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
    public void ignoresTheCaseOfTheSetting() throws Exception {
        final Map<String, String> props = issuerAndJwksUri();
        props.put("idToken.validate.enabled", "FALSE");

        assertAccepted(filterWith(props), signedIdToken(strangerKey));
    }

    @Test
    public void skipsValidationWithoutIssuerAndJwksUri() throws Exception {
        assertAccepted(filterWith(Collections.emptyMap()), signedIdToken(strangerKey));
    }

    @Test(expected = IllegalStateException.class)
    public void refusesToStartWhenRequiredWithoutIssuerAndJwksUri() {
        filterWith(Collections.singletonMap("idToken.validate.enabled", "true"));
    }

    @Test(expected = IllegalStateException.class)
    public void refusesToStartWhenRequiredWithMalformedJwksUri() {
        final Map<String, String> props = issuerAndJwksUri();
        props.put("jwksUri", "/jwks");
        props.put("idToken.validate.enabled", "true");

        filterWith(props);
    }

    @Test
    public void validatesTheSignedTokenInsideAnEncryptedIdToken() throws Exception {
        when(keystoreService.getEncryptionPrivateKey(PROVIDER)).thenReturn(encryptionKey.toPrivateKey());
        final OpenIdConnectFilter filter = filterWith(issuerAndJwksUri());

        assertAccepted(filter, encrypted(signedIdToken(signingKey)));
        assertRejected(filter, encrypted(signedIdToken(strangerKey)));
    }

    @Test
    public void warnsAtStartupWhenItCannotValidate() {
        final List<String> warnings = startupWarnings(filterWith(Collections.emptyMap()));

        assertEquals(1, warnings.size());
        assertTrue(warnings.get(0).contains("'" + PROVIDER + "' are not validated"));
    }

    @Test
    public void doesNotWarnAtStartupWhenValidationIsDisabled() {
        assertTrue(startupWarnings(filterWith(Collections.singletonMap("idToken.validate.enabled", "false"))).isEmpty());
    }

    @Test
    public void doesNotWarnAtStartupWhenItCanValidate() {
        assertTrue(startupWarnings(filterWith(issuerAndJwksUri())).isEmpty());
    }
}

package au.edu.qcif.xnat.auth.openid.jwt;

import au.edu.qcif.xnat.auth.openid.OpenIdAuthPlugin;
import com.github.tomakehurst.wiremock.junit.WireMockRule;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;

import java.util.Arrays;
import java.util.Date;

import static au.edu.qcif.xnat.auth.openid.etc.OpenIdAuthConstant.ID_TOKEN_ISSUER;
import static au.edu.qcif.xnat.auth.openid.etc.OpenIdAuthConstant.ISSUER;
import static au.edu.qcif.xnat.auth.openid.etc.OpenIdAuthConstant.JWKS_URI;
import static au.edu.qcif.xnat.auth.openid.gate.AuthPath.BEARER;
import static au.edu.qcif.xnat.auth.openid.gate.AuthPath.ID_TOKEN;
import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.stubFor;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static com.github.tomakehurst.wiremock.core.WireMockConfiguration.options;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.fail;
import static org.mockito.Mockito.lenient;

@RunWith(MockitoJUnitRunner.class)
public class JwtValidatorRegistryTest {

    @Rule
    public final WireMockRule wireMock = new WireMockRule(options().dynamicPort());

    @Mock private OpenIdAuthPlugin plugin;

    private void provider(final String providerId, final String issuer, final String jwksUri) {
        lenient().when(plugin.getProperty(providerId, ISSUER)).thenReturn(issuer);
        lenient().when(plugin.getProperty(providerId, JWKS_URI)).thenReturn(jwksUri);
    }

    private String serveJwks(final RSAKey key) {
        stubFor(get(urlEqualTo("/jwks")).willReturn(aResponse()
                .withStatus(200)
                .withHeader("Content-Type", "application/json")
                .withBody(new JWKSet(key.toPublicJWK()).toString())));
        return "http://localhost:" + wireMock.port() + "/jwks";
    }

    private static String signed(final RSAKey key, final String issuer) throws Exception {
        final SignedJWT jwt = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(key.getKeyID()).build(),
                new JWTClaimsSet.Builder()
                        .issuer(issuer)
                        .subject("alice")
                        .expirationTime(new Date(System.currentTimeMillis() + 3_600_000))
                        .build());
        jwt.sign(new RSASSASigner(key));
        return jwt.serialize();
    }

    @Test
    public void buildsValidatorsOnlyForProvidersWithIssuerAndJwksUri() {
        lenient().when(plugin.getEnabledProviders()).thenReturn(Arrays.asList("both", "issuerOnly", "neither"));
        provider("both", "https://idp.example", "https://idp.example/jwks");
        provider("issuerOnly", "https://idp.example", null);
        provider("neither", null, null);

        final JwtValidatorRegistry registry = new JwtValidatorRegistry(plugin);

        assertNotNull(registry.get("both", ID_TOKEN));
        assertNull(registry.get("issuerOnly", ID_TOKEN));
        assertNull(registry.get("neither", ID_TOKEN));
    }

    @Test
    public void skipsMalformedJwksUris() {
        lenient().when(plugin.getEnabledProviders()).thenReturn(Arrays.asList("relative", "unparseable", "unknownScheme"));
        provider("relative", "https://idp.example", "/jwks");
        provider("unparseable", "https://idp.example", "https://idp example/jwks");
        provider("unknownScheme", "https://idp.example", "nope://idp.example/jwks");

        final JwtValidatorRegistry registry = new JwtValidatorRegistry(plugin);

        assertNull(registry.get("relative", ID_TOKEN));
        assertNull(registry.get("unparseable", ID_TOKEN));
        assertNull(registry.get("unknownScheme", ID_TOKEN));
    }

    @Test
    public void trimsIssuerAndJwksUri() throws Exception {
        final RSAKey key = new RSAKeyGenerator(2048).keyID("k1").generate();
        lenient().when(plugin.getEnabledProviders()).thenReturn(Arrays.asList("padded"));
        provider("padded", " https://idp.example ", " " + serveJwks(key) + " ");

        final JwtValidator validator = new JwtValidatorRegistry(plugin).get("padded", ID_TOKEN);

        assertEquals("alice", validator.validate(signed(key, "https://idp.example")).getSubject());
    }

    @Test
    public void checksIdTokensAgainstIdTokenIssuerWhenSet() throws Exception {
        final RSAKey key = new RSAKeyGenerator(2048).keyID("k1").generate();
        lenient().when(plugin.getEnabledProviders()).thenReturn(Arrays.asList("entra"));
        provider("entra", "https://sts.example/tenant/", serveJwks(key));
        lenient().when(plugin.getProperty("entra", ID_TOKEN_ISSUER)).thenReturn("https://login.example/tenant/v2.0");

        final JwtValidatorRegistry registry = new JwtValidatorRegistry(plugin);

        assertEquals("alice", registry.get("entra", ID_TOKEN).validate(signed(key, "https://login.example/tenant/v2.0")).getSubject());
        assertEquals("alice", registry.get("entra", BEARER).validate(signed(key, "https://sts.example/tenant/")).getSubject());
        try {
            registry.get("entra", ID_TOKEN).validate(signed(key, "https://sts.example/tenant/"));
            fail("expected JwtValidationException");
        } catch (JwtValidationException expected) {
            // pass
        }
    }
}

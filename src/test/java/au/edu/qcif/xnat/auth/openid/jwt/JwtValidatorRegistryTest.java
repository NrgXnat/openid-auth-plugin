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

import static au.edu.qcif.xnat.auth.openid.etc.OpenIdAuthConstant.ISSUER;
import static au.edu.qcif.xnat.auth.openid.etc.OpenIdAuthConstant.JWKS_URI;
import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.stubFor;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static com.github.tomakehurst.wiremock.core.WireMockConfiguration.options;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
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

    @Test
    public void buildsValidatorsOnlyForProvidersWithIssuerAndJwksUri() {
        lenient().when(plugin.getEnabledProviders()).thenReturn(Arrays.asList("both", "issuerOnly", "neither"));
        provider("both", "https://idp.example", "https://idp.example/jwks");
        provider("issuerOnly", "https://idp.example", null);
        provider("neither", null, null);

        final JwtValidatorRegistry registry = new JwtValidatorRegistry(plugin);

        assertNotNull(registry.get("both"));
        assertNull(registry.get("issuerOnly"));
        assertNull(registry.get("neither"));
    }

    @Test
    public void skipsMalformedJwksUris() {
        lenient().when(plugin.getEnabledProviders()).thenReturn(Arrays.asList("relative", "unparseable", "unknownScheme"));
        provider("relative", "https://idp.example", "/jwks");
        provider("unparseable", "https://idp.example", "https://idp example/jwks");
        provider("unknownScheme", "https://idp.example", "nope://idp.example/jwks");

        final JwtValidatorRegistry registry = new JwtValidatorRegistry(plugin);

        assertNull(registry.get("relative"));
        assertNull(registry.get("unparseable"));
        assertNull(registry.get("unknownScheme"));
    }

    @Test
    public void trimsIssuerAndJwksUri() throws Exception {
        final RSAKey key = new RSAKeyGenerator(2048).keyID("k1").generate();
        stubFor(get(urlEqualTo("/jwks")).willReturn(aResponse()
                .withStatus(200)
                .withHeader("Content-Type", "application/json")
                .withBody(new JWKSet(key.toPublicJWK()).toString())));
        lenient().when(plugin.getEnabledProviders()).thenReturn(Arrays.asList("padded"));
        provider("padded", " https://idp.example ", " http://localhost:" + wireMock.port() + "/jwks ");

        final SignedJWT jwt = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.RS256).keyID("k1").build(),
                new JWTClaimsSet.Builder()
                        .issuer("https://idp.example")
                        .subject("alice")
                        .expirationTime(new Date(System.currentTimeMillis() + 3_600_000))
                        .build());
        jwt.sign(new RSASSASigner(key));

        assertEquals("alice", new JwtValidatorRegistry(plugin).get("padded").validate(jwt.serialize()).getSubject());
    }
}

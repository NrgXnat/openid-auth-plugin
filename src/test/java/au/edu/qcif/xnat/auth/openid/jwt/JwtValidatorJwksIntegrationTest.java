package au.edu.qcif.xnat.auth.openid.jwt;

import com.github.tomakehurst.wiremock.junit.WireMockRule;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;

import java.net.URL;
import java.util.Date;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.stubFor;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static com.github.tomakehurst.wiremock.core.WireMockConfiguration.options;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

/** Exercises {@link JwtValidator#remoteJwks} against a JWKS endpoint served by WireMock. */
public class JwtValidatorJwksIntegrationTest {

    private static final String ISSUER = "https://idp.example/realms/xnat";

    @Rule
    public final WireMockRule wireMock = new WireMockRule(options().dynamicPort());

    private static RSAKey publishedKey;   // kid "k1" — served by the JWKS endpoint
    private static RSAKey unpublishedKey;  // kid "k99" — never in the JWKS

    @BeforeClass
    public static void generateKeys() throws Exception {
        publishedKey = new RSAKeyGenerator(2048).keyID("k1").generate();
        unpublishedKey = new RSAKeyGenerator(2048).keyID("k99").generate();
    }

    private JwtValidator remoteValidator() throws Exception {
        stubFor(get(urlEqualTo("/jwks")).willReturn(aResponse()
                .withStatus(200)
                .withHeader("Content-Type", "application/json")
                .withBody(new JWKSet(publishedKey.toPublicJWK()).toString())));
        return new JwtValidator(ISSUER, JwtValidator.remoteJwks(new URL("http://localhost:" + wireMock.port() + "/jwks")));
    }

    private static String sign(final RSAKey key) throws Exception {
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

    @Test
    public void acceptsTokenSignedByPublishedKey() throws Exception {
        final JWTClaimsSet claims = remoteValidator().validate(sign(publishedKey));

        assertEquals("alice", claims.getSubject());
    }

    @Test
    public void rejectsTokenWithKidNotInJwks() throws Exception {
        final JwtValidator validator = remoteValidator();
        try {
            validator.validate(sign(unpublishedKey));
            fail("expected JwtValidationException");
        } catch (JwtValidationException expected) {
            // pass — no matching key in the JWKS
        }
    }
}

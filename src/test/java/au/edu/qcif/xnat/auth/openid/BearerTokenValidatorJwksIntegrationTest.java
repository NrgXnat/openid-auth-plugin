package au.edu.qcif.xnat.auth.openid;

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

/**
 * Integration test for {@link BearerTokenValidator#forRemoteJwks}: it fetches the issuer's public
 * keys from a JWKS endpoint (served here by WireMock) and uses them to verify the token signature.
 * Confirms the remote-JWKS wiring and JSON shape end to end — a token signed by the published key is
 * accepted, while a token whose {@code kid} is absent from the JWKS is rejected.
 */
public class BearerTokenValidatorJwksIntegrationTest {

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

    private BearerTokenValidator remoteValidator() throws Exception {
        stubFor(get(urlEqualTo("/jwks")).willReturn(aResponse()
                .withStatus(200)
                .withHeader("Content-Type", "application/json")
                .withBody(new JWKSet(publishedKey.toPublicJWK()).toString())));
        return BearerTokenValidator.forRemoteJwks(ISSUER, new URL("http://localhost:" + wireMock.port() + "/jwks"));
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
        final BearerTokenValidator validator = remoteValidator();
        try {
            validator.validate(sign(unpublishedKey));
            fail("expected BearerTokenValidationException");
        } catch (BearerTokenValidationException expected) {
            // pass — no matching key in the JWKS
        }
    }
}

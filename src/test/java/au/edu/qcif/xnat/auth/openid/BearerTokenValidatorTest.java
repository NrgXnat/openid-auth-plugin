package au.edu.qcif.xnat.auth.openid;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.PlainJWT;
import com.nimbusds.jwt.SignedJWT;
import org.junit.BeforeClass;
import org.junit.Test;

import java.util.Date;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

/**
 * Unit tests for {@link BearerTokenValidator}. A bearer access token arrives from an untrusted REST
 * client, so the validator must verify the signature against the issuer's keys and reject any token
 * with the wrong issuer, an expired/absent expiry, a bad signature, or an unsecured ({@code alg=none})
 * header.
 *
 * <p>Fully offline: a test RSA keypair signs the tokens and the validator is given the matching
 * public key via an in-memory {@link ImmutableJWKSet}, so no network or live IdP is involved.</p>
 */
public class BearerTokenValidatorTest {

    private static final String ISSUER = "https://idp.example/realms/xnat";

    private static RSAKey signingKey;     // kid "k1" — the issuer's real key
    private static RSAKey strangerKey;    // kid "k2" — a key the validator does NOT trust
    private static JWKSource<SecurityContext> trustedSource;

    @BeforeClass
    public static void generateKeys() throws Exception {
        signingKey = new RSAKeyGenerator(2048).keyID("k1").generate();
        strangerKey = new RSAKeyGenerator(2048).keyID("k2").generate();
        trustedSource = new ImmutableJWKSet<>(new JWKSet(signingKey.toPublicJWK()));
    }

    private static BearerTokenValidator validator() {
        return new BearerTokenValidator(ISSUER, trustedSource);
    }

    private static String signedToken(final RSAKey key, final JWTClaimsSet claims) throws Exception {
        final SignedJWT jwt = new SignedJWT(
                new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(key.getKeyID()).build(), claims);
        jwt.sign(new RSASSASigner(key));
        return jwt.serialize();
    }

    private static JWTClaimsSet.Builder validClaims() {
        return new JWTClaimsSet.Builder()
                .issuer(ISSUER)
                .subject("alice")
                .expirationTime(new Date(System.currentTimeMillis() + 3_600_000));
    }

    private static void assertRejected(final String token) {
        try {
            validator().validate(token);
            fail("expected BearerTokenValidationException");
        } catch (BearerTokenValidationException expected) {
            // pass
        }
    }

    @Test
    public void acceptsWellFormedToken() throws Exception {
        final JWTClaimsSet claims = validator().validate(signedToken(signingKey, validClaims().build()));
        assertEquals("alice", claims.getSubject());
        assertEquals(ISSUER, claims.getIssuer());
    }

    @Test
    public void rejectsTokenSignedByUntrustedKey() throws Exception {
        assertRejected(signedToken(strangerKey, validClaims().build()));
    }

    @Test
    public void rejectsWrongIssuer() throws Exception {
        assertRejected(signedToken(signingKey, validClaims().issuer("https://evil.example").build()));
    }

    @Test
    public void rejectsExpiredToken() throws Exception {
        final JWTClaimsSet expired = validClaims()
                .expirationTime(new Date(System.currentTimeMillis() - 3_600_000))
                .build();
        assertRejected(signedToken(signingKey, expired));
    }

    @Test
    public void rejectsTokenWithoutExpiry() throws Exception {
        final JWTClaimsSet noExp = new JWTClaimsSet.Builder().issuer(ISSUER).subject("alice").build();
        assertRejected(signedToken(signingKey, noExp));
    }

    @Test
    public void rejectsUnsecuredAlgNoneToken() throws Exception {
        assertRejected(new PlainJWT(validClaims().build()).serialize());
    }

    @Test
    public void rejectsGarbage() {
        assertRejected("not-a-jwt");
    }
}

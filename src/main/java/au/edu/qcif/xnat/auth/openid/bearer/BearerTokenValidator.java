package au.edu.qcif.xnat.auth.openid.bearer;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.jwk.source.JWKSourceBuilder;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.proc.DefaultJWTClaimsVerifier;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;

import java.net.URL;
import java.text.ParseException;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.Set;

/**
 * Cryptographically validates a bearer access token: it verifies the RSA signature against the
 * issuer's published keys and checks that the issuer matches and the token has not expired. A bearer
 * token arrives from an untrusted REST client (unlike the interactive ID token, which arrives over
 * TLS from the token endpoint), so this validation is the security boundary for the bearer path.
 *
 * <p>Only the asymmetric {@code RS256/384/512} algorithms are accepted; unsecured ({@code alg=none})
 * and symmetric (HMAC) tokens are rejected, closing off algorithm-confusion attacks. Audience is
 * deliberately <em>not</em> checked here — that policy belongs to the configurable {@code AudienceGate}
 * so all audience handling lives in one place.</p>
 *
 * <p>The {@link JWKSource} is injected, which is the seam that lets tests supply an in-memory public
 * key. {@link #forRemoteJwks(String, URL)} builds the production variant backed by a cached
 * {@code RemoteJWKSet} that re-fetches on key rotation.</p>
 */
class BearerTokenValidator {

    private static final Set<JWSAlgorithm> ACCEPTED_ALGORITHMS =
            new LinkedHashSet<>(java.util.Arrays.asList(JWSAlgorithm.RS256, JWSAlgorithm.RS384, JWSAlgorithm.RS512));

    private final DefaultJWTProcessor<SecurityContext> processor;

    BearerTokenValidator(final String expectedIssuer, final JWKSource<SecurityContext> jwkSource) {
        final DefaultJWTProcessor<SecurityContext> processor = new DefaultJWTProcessor<>();
        processor.setJWSKeySelector(new JWSVerificationKeySelector<>(ACCEPTED_ALGORITHMS, jwkSource));
        // Exact-match the issuer and require exp; DefaultJWTProcessor rejects unsecured (alg=none) JWTs
        // by default, and DefaultJWTClaimsVerifier enforces the expiry (with its default 60s skew).
        processor.setJWTClaimsSetVerifier(new DefaultJWTClaimsVerifier<>(
                new JWTClaimsSet.Builder().issuer(expectedIssuer).build(),
                Collections.singleton("exp")));
        this.processor = processor;
    }

    /**
     * Builds a validator whose keys are fetched from a remote JWKS endpoint and cached (with on-miss
     * refresh for key rotation), per the nimbus defaults.
     */
    static BearerTokenValidator forRemoteJwks(final String expectedIssuer, final URL jwksUri) {
        return new BearerTokenValidator(expectedIssuer, JWKSourceBuilder.create(jwksUri).build());
    }

    /**
     * @return the verified claims if the token's signature, issuer, and expiry all check out.
     * @throws BearerTokenValidationException on any validity failure (maps to 401).
     */
    JWTClaimsSet validate(final String rawJwt) throws BearerTokenValidationException {
        try {
            return processor.process(rawJwt, null);
        } catch (final ParseException | BadJOSEException | JOSEException e) {
            throw new BearerTokenValidationException("Bearer token failed validation: " + e.getMessage(), e);
        }
    }
}

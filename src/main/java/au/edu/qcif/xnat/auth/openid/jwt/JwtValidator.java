package au.edu.qcif.xnat.auth.openid.jwt;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jose.proc.DefaultJOSEObjectTypeVerifier;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.jwk.source.JWKSourceBuilder;
import com.nimbusds.jose.jwk.source.OutageTolerantJWKSetSource;
import com.nimbusds.jose.jwk.source.RateLimitReachedException;
import com.nimbusds.jose.jwk.source.RetryingJWKSetSource;
import com.nimbusds.jose.util.DefaultResourceRetriever;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.proc.DefaultJWTClaimsVerifier;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import lombok.extern.slf4j.Slf4j;

import java.net.URL;
import java.text.ParseException;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.Set;
import java.util.concurrent.TimeUnit;

/**
 * Verifies a JWT's signature, issuer, expiry and header {@code typ}. Only RS256/384/512 are accepted, which
 * rules out {@code alg=none} and HMAC algorithm confusion. Audience is left to the {@code AudienceGate}.
 */
@Slf4j
public class JwtValidator {

    private static final Set<JWSAlgorithm> ACCEPTED_ALGORITHMS =
            new LinkedHashSet<>(Arrays.asList(JWSAlgorithm.RS256, JWSAlgorithm.RS384, JWSAlgorithm.RS512));

    private static final long JWKS_CACHE_TTL_MS = 300_000;
    private static final long JWKS_OUTAGE_TOLERANCE_MS = 10 * JWKS_CACHE_TTL_MS;
    private static final long JWKS_REFETCH_MIN_INTERVAL_MS = 30_000;
    // Must exceed a fetch plus its retry, or requests queued behind the refresh give up.
    private static final long JWKS_CACHE_REFRESH_TIMEOUT_MS = 15_000;
    private static final int JWKS_CONNECT_TIMEOUT_MS = 2_000;
    private static final int JWKS_READ_TIMEOUT_MS = 4_000;

    // null accepts a token with no header typ
    public static final Set<JOSEObjectType> ID_TOKEN_TYPES = types(JOSEObjectType.JWT, null);
    public static final Set<JOSEObjectType> ACCESS_TOKEN_TYPES = types(JOSEObjectType.JWT, null,
            new JOSEObjectType("at+jwt"), new JOSEObjectType("application/at+jwt"));

    private final DefaultJWTProcessor<SecurityContext> processor;

    public JwtValidator(final String expectedIssuer, final JWKSource<SecurityContext> jwkSource,
                        final Set<JOSEObjectType> acceptedTypes) {
        final DefaultJWTProcessor<SecurityContext> processor = new DefaultJWTProcessor<>();
        processor.setJWSKeySelector(new JWSVerificationKeySelector<>(ACCEPTED_ALGORITHMS, jwkSource));
        processor.setJWSTypeVerifier(new DefaultJOSEObjectTypeVerifier<>(acceptedTypes));
        processor.setJWTClaimsSetVerifier(new DefaultJWTClaimsVerifier<>(
                new JWTClaimsSet.Builder().issuer(expectedIssuer).build(),
                Collections.singleton("exp")));
        this.processor = processor;
    }

    private static Set<JOSEObjectType> types(final JOSEObjectType... types) {
        return Collections.unmodifiableSet(new HashSet<>(Arrays.asList(types)));
    }

    public static JWKSource<SecurityContext> remoteJwks(final URL jwksUri) {
        final DefaultResourceRetriever retriever = new DefaultResourceRetriever(
                JWKS_CONNECT_TIMEOUT_MS, JWKS_READ_TIMEOUT_MS, JWKSourceBuilder.DEFAULT_HTTP_SIZE_LIMIT);
        return JWKSourceBuilder.create(jwksUri, retriever)
                .cache(JWKS_CACHE_TTL_MS, JWKS_CACHE_REFRESH_TIMEOUT_MS)
                .rateLimited(JWKS_REFETCH_MIN_INTERVAL_MS)
                .retrying(event -> {
                    if (event instanceof RetryingJWKSetSource.RetrialEvent<?> retrial) {
                        log.warn("Fetching JWKS from {} failed, retrying once: {}",
                                jwksUri, retrial.getException().getMessage());
                    }
                })
                .outageTolerant(JWKS_OUTAGE_TOLERANCE_MS, event -> {
                    if (event instanceof OutageTolerantJWKSetSource.OutageEvent<?> outage) {
                        log.warn("Could not refresh JWKS from {}: {}. Using the last fetched keys for up to {} more minutes.",
                                jwksUri, outage.getException().getMessage(),
                                TimeUnit.MILLISECONDS.toMinutes(outage.getRemainingTime()));
                    }
                })
                .build();
    }

    public JWTClaimsSet validate(final String rawJwt) throws JwtValidationException {
        try {
            return processor.process(rawJwt, null);
        } catch (final RateLimitReachedException e) {
            throw new JwtValidationException(
                    "No key in the cached JWKS matches the token, and the JWKS refetch rate limit has been reached", e);
        } catch (final ParseException | BadJOSEException | JOSEException e) {
            throw new JwtValidationException(e.getMessage(), e);
        }
    }
}

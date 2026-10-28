package au.edu.qcif.xnat.auth.openid.jwt;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.jwk.source.JWKSourceBuilder;
import com.nimbusds.jose.jwk.source.OutageTolerantJWKSetSource;
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
import java.util.LinkedHashSet;
import java.util.Set;
import java.util.concurrent.TimeUnit;

/**
 * Verifies a JWT's signature, issuer and expiry. Only RS256/384/512 are accepted, which rules out
 * {@code alg=none} and HMAC algorithm confusion. Audience is left to the {@code AudienceGate}.
 */
@Slf4j
public class JwtValidator {

    private static final Set<JWSAlgorithm> ACCEPTED_ALGORITHMS =
            new LinkedHashSet<>(Arrays.asList(JWSAlgorithm.RS256, JWSAlgorithm.RS384, JWSAlgorithm.RS512));

    // A fetch and its retry must finish within JWKSourceBuilder.DEFAULT_CACHE_REFRESH_TIMEOUT (15 s),
    // or requests queued behind the refresh give up.
    private static final int JWKS_CONNECT_TIMEOUT_MS = 2_000;
    private static final int JWKS_READ_TIMEOUT_MS = 4_000;
    private static final long JWKS_OUTAGE_TOLERANCE_MS = 10 * JWKSourceBuilder.DEFAULT_CACHE_TIME_TO_LIVE;

    private final DefaultJWTProcessor<SecurityContext> processor;

    public JwtValidator(final String expectedIssuer, final JWKSource<SecurityContext> jwkSource) {
        final DefaultJWTProcessor<SecurityContext> processor = new DefaultJWTProcessor<>();
        processor.setJWSKeySelector(new JWSVerificationKeySelector<>(ACCEPTED_ALGORITHMS, jwkSource));
        processor.setJWTClaimsSetVerifier(new DefaultJWTClaimsVerifier<>(
                new JWTClaimsSet.Builder().issuer(expectedIssuer).build(),
                Collections.singleton("exp")));
        this.processor = processor;
    }

    public static JWKSource<SecurityContext> remoteJwks(final URL jwksUri) {
        final DefaultResourceRetriever retriever = new DefaultResourceRetriever(
                JWKS_CONNECT_TIMEOUT_MS, JWKS_READ_TIMEOUT_MS, JWKSourceBuilder.DEFAULT_HTTP_SIZE_LIMIT);
        return JWKSourceBuilder.create(jwksUri, retriever)
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
        } catch (final ParseException | BadJOSEException | JOSEException e) {
            throw new JwtValidationException(e.getMessage(), e);
        }
    }
}

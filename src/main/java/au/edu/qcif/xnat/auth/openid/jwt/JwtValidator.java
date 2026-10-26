package au.edu.qcif.xnat.auth.openid.jwt;

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
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.Set;

/**
 * Verifies a JWT's signature, issuer and expiry. Only RS256/384/512 are accepted, which rules out
 * {@code alg=none} and HMAC algorithm confusion. Audience is left to the {@code AudienceGate}.
 */
public class JwtValidator {

    private static final Set<JWSAlgorithm> ACCEPTED_ALGORITHMS =
            new LinkedHashSet<>(Arrays.asList(JWSAlgorithm.RS256, JWSAlgorithm.RS384, JWSAlgorithm.RS512));

    private final DefaultJWTProcessor<SecurityContext> processor;

    public JwtValidator(final String expectedIssuer, final JWKSource<SecurityContext> jwkSource) {
        final DefaultJWTProcessor<SecurityContext> processor = new DefaultJWTProcessor<>();
        processor.setJWSKeySelector(new JWSVerificationKeySelector<>(ACCEPTED_ALGORITHMS, jwkSource));
        processor.setJWTClaimsSetVerifier(new DefaultJWTClaimsVerifier<>(
                new JWTClaimsSet.Builder().issuer(expectedIssuer).build(),
                Collections.singleton("exp")));
        this.processor = processor;
    }

    public static JwtValidator forRemoteJwks(final String expectedIssuer, final URL jwksUri) {
        return new JwtValidator(expectedIssuer, JWKSourceBuilder.create(jwksUri).build());
    }

    public JWTClaimsSet validate(final String rawJwt) throws JwtValidationException {
        try {
            return processor.process(rawJwt, null);
        } catch (final ParseException | BadJOSEException | JOSEException e) {
            throw new JwtValidationException(e.getMessage(), e);
        }
    }
}

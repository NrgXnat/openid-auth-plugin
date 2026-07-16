package au.edu.qcif.xnat.auth.openid.gate;

import com.nimbusds.jwt.JWTClaimsSet;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * The parsed token a {@link ClaimGate} inspects: the validated {@link JWTClaimsSet} (the token
 * <em>body</em>) plus the JWT <em>header</em> as a {@code Map<String,Object>}.
 *
 * <p>Both authentication paths produce a {@code JWTClaimsSet}; exposing the header alongside it lets
 * a gate read header parameters (such as {@code typ}, which some providers place in the header rather
 * than the body) without the gate having to know which path it is running on. The header mirrors how
 * {@link JWTClaimsSet#getClaims()} exposes the body — a plain map — so header-based gates can walk it
 * the same way {@link ClaimPaths} walks nested claims.</p>
 */
public final class TokenContext {

    private final JWTClaimsSet claims;
    private final Map<String, Object> headers;

    public TokenContext(final JWTClaimsSet claims, final Map<String, Object> headers) {
        this.claims = claims;
        this.headers = headers == null
                ? Collections.emptyMap()
                : Collections.unmodifiableMap(new LinkedHashMap<>(headers));
    }

    /** A context with no header (e.g. when only the claims are available, as in unit tests). */
    public static TokenContext of(final JWTClaimsSet claims) {
        return new TokenContext(claims, Collections.emptyMap());
    }

    public static TokenContext of(final JWTClaimsSet claims, final Map<String, Object> headers) {
        return new TokenContext(claims, headers);
    }

    /** The validated, parsed token claims (the JWT body). */
    public JWTClaimsSet claims() {
        return claims;
    }

    /** The JWT header parameters; never {@code null} (an empty map when no header is available). */
    public Map<String, Object> headers() {
        return headers;
    }
}

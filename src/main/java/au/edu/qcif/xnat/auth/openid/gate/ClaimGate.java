package au.edu.qcif.xnat.auth.openid.gate;

import com.nimbusds.jwt.JWTClaimsSet;

/**
 * An authorization gate that inspects a validated, parsed {@link JWTClaimsSet} and rejects callers
 * who fail its check. Gates operate purely on the structured claims, so the same gate serves both
 * the interactive ID-token path and the bearer-token path.
 */
public interface ClaimGate {

    /**
     * @param claims the validated, parsed token claims
     * @throws ClaimGateException if the claims fail this gate
     */
    void check(JWTClaimsSet claims) throws ClaimGateException;
}

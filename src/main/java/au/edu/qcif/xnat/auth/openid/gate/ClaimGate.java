package au.edu.qcif.xnat.auth.openid.gate;

/**
 * An authorization gate that inspects a validated, parsed {@link TokenContext} (the token claims
 * plus its JWT header) and rejects callers who fail its check. Gates operate purely on the parsed
 * token, so the same gate serves both the interactive ID-token path and the bearer-token path.
 */
public interface ClaimGate {

    /**
     * @param token the validated, parsed token (claims and header)
     * @throws ClaimGateException if the token fails this gate
     */
    void check(TokenContext token) throws ClaimGateException;
}

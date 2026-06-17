package au.edu.qcif.xnat.auth.openid.gate;

/**
 * Thrown when a valid, parsed token fails an authorization gate.
 *
 * <p>Deliberately <strong>not</strong> a {@code BadCredentialsException} subclass: a gate failure
 * means the credential is valid but the caller is not authorized, which is a different condition
 * from a bad, expired, or wrong-issuer token. Each authentication path maps this exception to its
 * own outcome — the bearer path to 403 Forbidden, the interactive ID-token path to its existing
 * login-redirect failure handling.</p>
 */
public class ClaimGateException extends RuntimeException {

    public ClaimGateException(final String message) {
        super(message);
    }
}

package au.edu.qcif.xnat.auth.openid.bearer;

/**
 * Thrown when a bearer token fails validity checking — a bad signature, wrong issuer, expired or
 * missing expiry, or an otherwise unparseable/unsecured token.
 *
 * <p>This is the <strong>401 Unauthorized</strong> condition: the credential itself is invalid. It
 * is deliberately distinct from {@code ClaimGateException} (a valid token that is not authorized,
 * mapped to 403) — re-minting a fresh token can fix a 401 but never a 403.</p>
 */
class BearerTokenValidationException extends Exception {

    BearerTokenValidationException(final String message, final Throwable cause) {
        super(message, cause);
    }
}

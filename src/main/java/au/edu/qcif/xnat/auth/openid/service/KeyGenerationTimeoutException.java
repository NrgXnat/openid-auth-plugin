package au.edu.qcif.xnat.auth.openid.service;

/**
 * Exception thrown when a non-primary node times out waiting for the primary node
 * to generate an encryption key.
 */
public class KeyGenerationTimeoutException extends Exception {

    public KeyGenerationTimeoutException(final String message) {
        super(message);
    }

    public KeyGenerationTimeoutException(final String message, final Throwable cause) {
        super(message, cause);
    }
}

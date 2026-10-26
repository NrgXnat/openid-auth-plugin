package au.edu.qcif.xnat.auth.openid.jwt;

public class JwtValidationException extends Exception {

    JwtValidationException(final String message, final Throwable cause) {
        super(message, cause);
    }
}

package au.edu.qcif.xnat.auth.openid;

import org.springframework.security.authentication.AuthenticationServiceException;

/**
 * Thrown when an OpenID identity has an XNAT account mapping but the account could not be loaded, or
 * when whether a mapping exists could not be determined. Either way it says nothing about whether the
 * person may sign in, so neither path may treat it as a missing mapping and go on to link, create or
 * deny: the bearer path answers 503, and the interactive path fails the login.
 */
public class AccountUnavailableException extends AuthenticationServiceException {

    public AccountUnavailableException(final String message) {
        super(message);
    }

    public AccountUnavailableException(final String message, final Throwable cause) {
        super(message, cause);
    }
}

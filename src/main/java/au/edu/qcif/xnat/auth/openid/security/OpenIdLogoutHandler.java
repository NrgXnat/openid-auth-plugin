package au.edu.qcif.xnat.auth.openid.security;

import au.edu.qcif.xnat.auth.openid.OpenIdAuthPlugin;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.logout.LogoutHandler;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import static au.edu.qcif.xnat.auth.openid.OpenIdConnectFilter.AUTO_LOGIN_SUPPRESS_COOKIE;
import static au.edu.qcif.xnat.auth.openid.OpenIdConnectFilter.ID_TOKEN_SESSION_ATTR;
import static au.edu.qcif.xnat.auth.openid.etc.OpenIdAuthConstant.LOGOUT_URI;

/**
 * Logout-time preparation for the OpenID auto-login feature. It runs before Spring Security invalidates the
 * session (Spring appends its session-invalidating handler after the custom ones), and stops a logout from
 * being immediately undone by auto-login. It does exactly one of two things (never both), depending on the
 * logout strategy:
 * <ul>
 *   <li><b>Unified logout</b> ({@code logoutUri} set): stash the login's id_token in a request attribute so
 *   {@link RpInitiatedLogoutSuccessHandler} can send it as {@code id_token_hint} and end the provider session.
 *   No suppression cookie — the redirect to {@code logoutUri} handles it, and a lingering cookie would wrongly
 *   block auto-login after the user next signs in. On an idle timeout the id_token is already gone with the
 *   expired session; the logout is still attempted at the provider (see {@link RpInitiatedLogoutSuccessHandler}),
 *   it just can't carry the hint.</li>
 *   <li><b>Local logout</b> ({@code logoutUri} unset): set a cookie telling the login-screen extension to skip
 *   auto-login until the user signs in again, since there is no end-session endpoint to redirect to.</li>
 * </ul>
 * Gated on a provider having {@code autoLogin} enabled, so this is inert otherwise.
 */
@Slf4j
public class OpenIdLogoutHandler implements LogoutHandler {

    /** Request attribute carrying the id_token from the (about-to-be-invalidated) session to the success handler. */
    static final String ID_TOKEN_HINT_ATTRIBUTE = "au.edu.qcif.xnat.auth.openid.idTokenHint";

    private final OpenIdAuthPlugin plugin;

    public OpenIdLogoutHandler(final OpenIdAuthPlugin plugin) {
        this.plugin = plugin;
    }

    @Override
    public void logout(final HttpServletRequest request, final HttpServletResponse response, final Authentication authentication) {
        final String autoLoginProvider = plugin.getAutoLoginProviderId();
        if (autoLoginProvider == null) {
            return;
        }
        if (StringUtils.isNotBlank(plugin.getProperty(autoLoginProvider, LOGOUT_URI))) {
            // Unified logout: hand the id_token (when the session is still live) to the success handler as
            // id_token_hint. On an idle timeout it's already gone; the success handler still attempts logout.
            captureIdToken(request);
        } else {
            // Local logout: no end-session endpoint, so suppress the next auto-login instead.
            setSuppressionCookie(request, response);
        }
    }

    private void captureIdToken(final HttpServletRequest request) {
        final HttpSession session = request.getSession(false);
        if (session == null) {
            return;
        }
        final Object idToken = session.getAttribute(ID_TOKEN_SESSION_ATTR);
        if (idToken != null) {
            request.setAttribute(ID_TOKEN_HINT_ATTRIBUTE, idToken);
        }
    }

    private void setSuppressionCookie(final HttpServletRequest request, final HttpServletResponse response) {
        final Cookie cookie = new Cookie(AUTO_LOGIN_SUPPRESS_COOKIE, "1");
        cookie.setPath("/");
        cookie.setHttpOnly(true);
        cookie.setSecure(request.isSecure());
        // Session cookie (no max-age): cleared on browser close or on the next explicit sign-in.
        response.addCookie(cookie);
        log.debug("Set auto-login suppression cookie on logout");
    }
}

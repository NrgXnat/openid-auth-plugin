package au.edu.qcif.xnat.auth.openid.security;

import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.nrg.xdat.XDAT;
import org.nrg.xnat.utils.InteractiveAgentDetector;
import org.springframework.security.web.session.InvalidSessionStrategy;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;

import static au.edu.qcif.xnat.auth.openid.etc.Navigations.isNavigation;

/**
 * For a deployment where the provider, not XNAT, decides whether a user is signed in ({@code session.onInvalid=reauth}).
 * A browser that still holds an XNAT session cookie XNAT no longer recognises (the session lapsed overnight, or XNAT
 * restarted) is sent through sign-in again instead of to logout, so auto-login can find the live provider session.
 * With a {@code logoutUri} that ends the SSO session, routing it to logout would sign the user out of every
 * application on the provider.
 *
 * <p>A page load gets a new, anonymous session (replacing the stale cookie) and is redirected to the same URL, which
 * then takes the ordinary signed-out path through the login page and auto-login, back to the requested page. A form
 * submission can't be kept (its CSRF token belonged to the old session), so it is redirected to the page it was
 * submitted from, or to the site root without a same-origin {@code Referer}.</p>
 *
 * <p>Any other browser request (XHR, {@code fetch}, a stylesheet) is sent to the login page, as XNAT sends any signed-out
 * page script, and an API client gets a 401. Neither goes through logout: the stale cookie may be one that another
 * window's sign-in has just replaced, and by the time a redirect to logout is followed, the browser sends the new
 * cookie, so the logout would end the session that window just created. A browser gets no 401 because a proxy in front
 * may answer a 401 with its own sign-in page, ending the user's session there.</p>
 */
@Slf4j
public class ReauthInvalidSessionStrategy implements InvalidSessionStrategy {

    private static final String XNAT_LOGIN_PATH = "/app/template/Login.vm";

    @Override
    public void onInvalidSessionDetected(final HttpServletRequest request, final HttpServletResponse response) throws IOException {
        if (!isNavigation(request)) {
            if (LogoutRedirectInvalidSessionStrategy.isInteractive(request, resolveDetector())) {
                response.sendRedirect(request.getContextPath() + XNAT_LOGIN_PATH);
            } else {
                response.sendError(HttpServletResponse.SC_UNAUTHORIZED);
            }
            return;
        }
        final String target = target(request);
        log.debug("Expired session on a page load; signing in again at {}", target);
        // The container sets the new session's cookie itself, so it replaces the stale one whatever its path.
        request.getSession(true);
        response.setStatus(HttpServletResponse.SC_SEE_OTHER);
        response.setHeader("Location", target);
    }

    /** XNAT's interactive-agent detector, or {@code null} if unavailable; isolated so tests can supply one. */
    InteractiveAgentDetector resolveDetector() {
        return XDAT.getContextService().getBeanSafely(InteractiveAgentDetector.class);
    }

    /** The URL to sign in again at: the requested one for a GET, otherwise the form's page or the site root. */
    private static String target(final HttpServletRequest request) {
        if ("GET".equals(request.getMethod())) {
            final String query = request.getQueryString();
            return request.getRequestURI() + (query != null ? "?" + query : "");
        }
        final String referer = sameOriginReferer(request);
        return referer != null ? referer : request.getContextPath() + "/";
    }

    /**
     * The path and query of the {@code Referer}, if it is a page of this XNAT. Only the path is used, so the redirect
     * can't leave the site.
     */
    static String sameOriginReferer(final HttpServletRequest request) {
        final String referer = request.getHeader("Referer");
        if (referer == null) {
            return null;
        }
        final URI uri;
        try {
            uri = new URI(referer);
        } catch (URISyntaxException e) {
            return null;
        }
        // Sec-Fetch-Site is set by the browser; without it, compare hosts, since a proxy in front may change the scheme.
        final String site = request.getHeader("Sec-Fetch-Site");
        final boolean sameOrigin = site != null ? "same-origin".equals(site) : StringUtils.equalsIgnoreCase(uri.getHost(), request.getServerName());
        final String path = uri.getRawPath();
        final String contextPath = request.getContextPath();
        if (!sameOrigin || path == null || !(path.equals(contextPath) || path.startsWith(contextPath + "/"))) {
            return null;
        }
        return path + (uri.getRawQuery() != null ? "?" + uri.getRawQuery() : "");
    }
}

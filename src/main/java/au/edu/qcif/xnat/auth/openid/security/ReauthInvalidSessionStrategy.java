package au.edu.qcif.xnat.auth.openid.security;

import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.springframework.security.web.session.InvalidSessionStrategy;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;

/**
 * For a deployment where the provider, not XNAT, decides whether a user is signed in ({@code session.onInvalid=reauth}).
 * A browser that still holds an XNAT session cookie XNAT no longer recognises (the session lapsed overnight, or XNAT
 * restarted) is sent through sign-in again instead of to logout, so auto-login can find the live provider session.
 * With a {@code logoutUri} that ends the SSO session, routing it to logout would sign the user out of every
 * application on the provider.
 *
 * <p>Only page loads are handled this way: the request gets a new, anonymous session (replacing the stale cookie) and
 * is redirected to the same URL, which then takes the ordinary signed-out path through the login page and
 * auto-login, back to the requested page. A form submission can't be kept (its CSRF token belonged to the old
 * session), so it is redirected to the page it was submitted from instead. Background requests, and form submissions
 * without a same-origin {@code Referer}, go to {@code fallback}, since a redirect can't sign in an XHR.</p>
 */
@Slf4j
public class ReauthInvalidSessionStrategy implements InvalidSessionStrategy {

    private final InvalidSessionStrategy fallback;

    public ReauthInvalidSessionStrategy(final InvalidSessionStrategy fallback) {
        this.fallback = fallback;
    }

    @Override
    public void onInvalidSessionDetected(final HttpServletRequest request, final HttpServletResponse response) throws IOException, ServletException {
        final String target = isNavigation(request) ? target(request) : null;
        if (target == null) {
            fallback.onInvalidSessionDetected(request, response);
            return;
        }
        log.debug("Expired session on a page load; signing in again at {}", target);
        // The container sets the new session's cookie itself, so it replaces the stale one whatever its path.
        request.getSession(true);
        response.setStatus(HttpServletResponse.SC_SEE_OTHER);
        response.setHeader("Location", target);
    }

    /** The URL to sign in again at: the requested one for a GET, the form's page for a POST, otherwise none. */
    private static String target(final HttpServletRequest request) {
        switch (request.getMethod()) {
            case "GET":
                final String query = request.getQueryString();
                return request.getRequestURI() + (query != null ? "?" + query : "");
            case "POST":
                return sameOriginReferer(request);
            default:
                return null;
        }
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

    /**
     * True for a top-level page load. Browsers send {@code Sec-Fetch-*}, which scripts can't set; without it, a request
     * for HTML counts unless it carries {@code X-Requested-With}, since some of XNAT's XHRs ask for HTML too.
     */
    static boolean isNavigation(final HttpServletRequest request) {
        final String mode = request.getHeader("Sec-Fetch-Mode");
        if (mode != null) {
            final String dest = request.getHeader("Sec-Fetch-Dest");
            return "navigate".equals(mode) && (dest == null || "document".equals(dest));
        }
        return StringUtils.contains(request.getHeader("Accept"), "text/html") && request.getHeader("X-Requested-With") == null;
    }
}

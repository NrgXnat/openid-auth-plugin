package au.edu.qcif.xnat.auth.openid.security;

import lombok.extern.slf4j.Slf4j;
import org.nrg.xdat.XDAT;
import org.nrg.xnat.utils.InteractiveAgentDetector;
import org.springframework.security.web.session.InvalidSessionStrategy;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * When auto-login is enabled, a request bearing an expired session id (an idle XNAT "auto-logout") must not be
 * quietly turned into a fresh anonymous session, or the login screen would automatically log the user straight
 * back in. Spring Security's {@code SessionManagementFilter} detects the invalid session id on the
 * <em>original</em> request — before XNAT creates a new session for the login redirect, which is why this can't
 * be detected on the login page itself — and invokes this strategy.
 *
 * <p>Interactive (browser) requests are routed to XNAT's logout so the timeout behaves like clicking Logout
 * (unified up to {@code logoutUri}, or local). Non-interactive requests (e.g. a REST client carrying only a
 * stale session cookie) get a 401 instead of a redirect.</p>
 */
@Slf4j
public class LogoutRedirectInvalidSessionStrategy implements InvalidSessionStrategy {

    private static final String XNAT_LOGOUT_PATH = "/app/action/LogoutUser";

    @Override
    public void onInvalidSessionDetected(final HttpServletRequest request, final HttpServletResponse response) throws IOException {
        if (isInteractive(request)) {
            log.debug("Expired session on an interactive request; routing to logout");
            response.sendRedirect(request.getContextPath() + XNAT_LOGOUT_PATH);
        } else {
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED);
        }
    }

    /**
     * Browser-vs-API decision, reusing XNAT's own {@link InteractiveAgentDetector} (the same detector
     * {@code XnatAuthenticationEntryPoint} uses) so a browser AJAX call still counts as interactive instead of
     * being misread as an API client. Mirrors the entry point: only a non-interactive agent on a data path is
     * treated as API. Falls back to an Accept-header check if the detector bean can't be resolved.
     */
    private boolean isInteractive(final HttpServletRequest request) {
        final InteractiveAgentDetector detector = resolveDetector();
        if (detector != null) {
            return !(detector.isDataPath(request) && !detector.isInteractiveAgent(request));
        }
        final String accept = request.getHeader("Accept");
        return accept != null && accept.contains("text/html");
    }

    /** XNAT's interactive-agent detector, or {@code null} if unavailable; isolated so tests can supply one. */
    InteractiveAgentDetector resolveDetector() {
        return XDAT.getContextService().getBeanSafely(InteractiveAgentDetector.class);
    }
}

package au.edu.qcif.xnat.auth.openid.bearer;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;
import javax.servlet.http.HttpSession;

/**
 * Wraps an authenticated bearer request so the downstream filter chain can never make the servlet
 * container create an {@link HttpSession} (and therefore never emit a {@code JSESSIONID} cookie).
 *
 * <p>The {@code @Transient} {@link BearerAuthToken} stops Spring Security's
 * {@code SecurityContextPersistenceFilter} from persisting the authentication into a session, but it
 * does <em>not</em> stop other downstream callers from creating one. In particular XNAT's
 * {@code org.nrg.xnat.security.XnatExpiredPasswordFilter} calls {@code request.getSession()}
 * unconditionally on every request, which makes the container mint a session — and a cookie — even
 * for a stateless REST call. This wrapper intercepts session acquisition:</p>
 *
 * <ul>
 *   <li>{@code getSession(false)} returns a genuinely pre-existing container session if one somehow
 *       exists, otherwise {@code null} — so Spring Security's {@code SessionManagementFilter} and its
 *       session-fixation strategy correctly see a sessionless request and stay no-ops.</li>
 *   <li>{@code getSession(true)} / {@code getSession()} return a single per-request
 *       {@link EphemeralHttpSession} that satisfies callers which immediately dereference the session,
 *       but is never registered with the container, so no cookie is written.</li>
 * </ul>
 *
 * <p>The wrapper is applied only on the successful bearer-authentication path; ordinary
 * session/basic-auth requests are passed through unwrapped and keep their normal session behavior.</p>
 */
final class StatelessSessionRequestWrapper extends HttpServletRequestWrapper {

    private EphemeralHttpSession ephemeralSession;

    StatelessSessionRequestWrapper(final HttpServletRequest request) {
        super(request);
    }

    @Override
    public HttpSession getSession(final boolean create) {
        // Respect a real pre-existing container session (not expected on the bearer path, but correct).
        final HttpSession existing = super.getSession(false);
        if (existing != null) {
            return existing;
        }
        if (!create) {
            return null;
        }
        if (ephemeralSession == null) {
            ephemeralSession = new EphemeralHttpSession(getServletContext());
        }
        return ephemeralSession;
    }

    @Override
    public HttpSession getSession() {
        return getSession(true);
    }
}

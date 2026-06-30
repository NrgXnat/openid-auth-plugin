package au.edu.qcif.xnat.auth.openid.bearer;

import java.util.Collections;
import java.util.Enumeration;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import javax.servlet.ServletContext;
import javax.servlet.http.HttpSession;
import javax.servlet.http.HttpSessionContext;

/**
 * A throwaway {@link HttpSession} that lives only for the duration of one request and is never
 * registered with the servlet container, so the container never emits a {@code JSESSIONID} cookie
 * for it.
 *
 * <p>It exists solely to keep the bearer path stateless (see {@link StatelessSessionRequestWrapper}).
 * Downstream XNAT filters — notably {@code org.nrg.xnat.security.XnatExpiredPasswordFilter} — call
 * {@code request.getSession()} unconditionally and immediately dereference the result (e.g.
 * {@code getMaxInactiveInterval()}, {@code getAttribute(...)}), so returning {@code null} is not an
 * option. This implementation satisfies that contract with an in-memory attribute map; any state it
 * holds is discarded when the request completes, which is exactly the desired semantics for a
 * stateless, token-authenticated REST call.</p>
 */
final class EphemeralHttpSession implements HttpSession {

    private final ServletContext servletContext;
    private final Map<String, Object> attributes = new ConcurrentHashMap<>();
    private final String id = UUID.randomUUID().toString();
    private final long creationTime = System.currentTimeMillis();
    private int maxInactiveInterval = 1800;
    private volatile boolean invalidated = false;

    EphemeralHttpSession(final ServletContext servletContext) {
        this.servletContext = servletContext;
    }

    @Override
    public long getCreationTime() {
        return creationTime;
    }

    @Override
    public String getId() {
        return id;
    }

    @Override
    public long getLastAccessedTime() {
        return creationTime;
    }

    @Override
    public ServletContext getServletContext() {
        return servletContext;
    }

    @Override
    public void setMaxInactiveInterval(final int interval) {
        this.maxInactiveInterval = interval;
    }

    @Override
    public int getMaxInactiveInterval() {
        return maxInactiveInterval;
    }

    @Override
    @SuppressWarnings("deprecation")
    public HttpSessionContext getSessionContext() {
        return null;
    }

    @Override
    public Object getAttribute(final String name) {
        return attributes.get(name);
    }

    @Override
    @SuppressWarnings("deprecation")
    public Object getValue(final String name) {
        return getAttribute(name);
    }

    @Override
    public Enumeration<String> getAttributeNames() {
        return Collections.enumeration(attributes.keySet());
    }

    @Override
    @SuppressWarnings("deprecation")
    public String[] getValueNames() {
        return attributes.keySet().toArray(new String[0]);
    }

    @Override
    public void setAttribute(final String name, final Object value) {
        if (value == null) {
            attributes.remove(name);
        } else {
            attributes.put(name, value);
        }
    }

    @Override
    @SuppressWarnings("deprecation")
    public void putValue(final String name, final Object value) {
        setAttribute(name, value);
    }

    @Override
    public void removeAttribute(final String name) {
        attributes.remove(name);
    }

    @Override
    @SuppressWarnings("deprecation")
    public void removeValue(final String name) {
        removeAttribute(name);
    }

    @Override
    public void invalidate() {
        attributes.clear();
        invalidated = true;
    }

    @Override
    public boolean isNew() {
        return true;
    }

    /** Whether {@link #invalidate()} has been called; not part of the API, used only for assertions/tests. */
    boolean isInvalidated() {
        return invalidated;
    }
}

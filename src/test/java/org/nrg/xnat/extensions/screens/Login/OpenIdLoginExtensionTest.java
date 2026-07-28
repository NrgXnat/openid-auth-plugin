package org.nrg.xnat.extensions.screens.Login;

import au.edu.qcif.xnat.auth.openid.OpenIdAuthPlugin;
import org.apache.turbine.util.RunData;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;
import org.nrg.xft.security.UserI;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.util.HashMap;
import java.util.Map;

import static au.edu.qcif.xnat.auth.openid.OpenIdConnectFilter.AUTO_LOGIN_ATTEMPTED_COOKIE;
import static au.edu.qcif.xnat.auth.openid.OpenIdConnectFilter.OPENID_ERROR_MESSAGE;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.any;
import static org.mockito.Mockito.anyString;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link OpenIdLoginExtension}. The core decision logic is exercised through the package-private
 * {@link OpenIdLoginExtension#handle} entry point with mocked collaborators, so no servlet container or XNAT
 * runtime is required; the static XNAT lookups in {@code execute()} are stubbed out via overridable seams.
 */
@RunWith(MockitoJUnitRunner.class)
public class OpenIdLoginExtensionTest {

    private static final String SERVER = "https://xnat.example";

    @Mock private RunData             data;
    @Mock private HttpSession         session;
    @Mock private HttpServletRequest  request;
    @Mock private HttpServletResponse response;
    @Mock private UserI               guestUser;
    @Mock private UserI               realUser;
    @Mock private OpenIdAuthPlugin    plugin;

    private OpenIdLoginExtension extension;

    @Before
    public void setUp() {
        extension = new OpenIdLoginExtension() {
            @Override String fullServerPath() { return SERVER; }
            @Override UserI resolveCurrentUser() { return null; }
            @Override OpenIdAuthPlugin resolvePlugin() { return null; }
        };
    }

    // ---- error-message display -----------------------------------------------------------------

    @Test
    public void displaysAndClearsErrorMessageWhenPresent() throws Exception {
        when(data.getSession()).thenReturn(session);
        when(session.getAttribute(OPENID_ERROR_MESSAGE)).thenReturn("Your email domain is not permitted");

        extension.handle(data, guestUser, plugin);

        verify(data).setMessage("Your email domain is not permitted");
        // The one-shot message is removed so it does not reappear on the next page load.
        verify(session).removeAttribute(OPENID_ERROR_MESSAGE);
        // A pending error message must not be masked by an auto-login redirect.
        verify(response, never()).sendRedirect(anyString());
    }

    // ---- auto-login redirect -------------------------------------------------------------------

    @Test
    public void redirectsAnonymousUserWhenAProviderOptsIn() throws Exception {
        when(data.getSession()).thenReturn(session);
        when(data.getResponse()).thenReturn(response);
        when(data.getRequest()).thenReturn(request);
        when(guestUser.isGuest()).thenReturn(true);
        when(plugin.getAutoLoginProviderId()).thenReturn("keycloak");

        extension.handle(data, guestUser, plugin);

        // A short-lived, one-shot guard cookie is set so a failed auto-login attempt cannot loop.
        final ArgumentCaptor<Cookie> cookieCaptor = ArgumentCaptor.forClass(Cookie.class);
        verify(response).addCookie(cookieCaptor.capture());
        final Cookie guard = cookieCaptor.getValue();
        assertEquals(AUTO_LOGIN_ATTEMPTED_COOKIE, guard.getName());
        assertEquals(120, guard.getMaxAge());
        assertTrue("guard cookie must be HttpOnly", guard.isHttpOnly());

        verify(response).sendRedirect(SERVER + "/openid-login?providerId=keycloak&prompt=none");
        verify(data, never()).setMessage(anyString());
    }

    @Test
    public void doesNotRedirectAuthenticatedUser() throws Exception {
        when(data.getSession()).thenReturn(session);
        when(data.getResponse()).thenReturn(response);
        when(realUser.isGuest()).thenReturn(false);

        extension.handle(data, realUser, plugin);

        verify(response, never()).sendRedirect(anyString());
        verify(response, never()).addCookie(any(Cookie.class));
    }

    @Test
    public void doesNotRedirectWhenResponseAlreadyCommitted() throws Exception {
        when(data.getSession()).thenReturn(session);
        when(data.getResponse()).thenReturn(response);
        when(response.isCommitted()).thenReturn(true);

        extension.handle(data, guestUser, plugin);

        verify(response, never()).sendRedirect(anyString());
    }

    @Test
    public void doesNotRedirectWhenGuardCookiePresent() throws Exception {
        // The guard cookie from a previous auto-login attempt is present; do not redirect again (no loop).
        when(data.getSession()).thenReturn(session);
        when(data.getResponse()).thenReturn(response);
        when(data.getRequest()).thenReturn(request);
        when(guestUser.isGuest()).thenReturn(true);
        when(request.getCookies()).thenReturn(new Cookie[]{new Cookie(AUTO_LOGIN_ATTEMPTED_COOKIE, "1")});

        extension.handle(data, guestUser, plugin);

        verify(response, never()).sendRedirect(anyString());
        verify(response, never()).addCookie(any(Cookie.class));
    }

    @Test
    public void doesNotRedirectWhenNoProviderOptsIn() throws Exception {
        when(data.getSession()).thenReturn(session);
        when(data.getResponse()).thenReturn(response);
        when(data.getRequest()).thenReturn(request);
        when(guestUser.isGuest()).thenReturn(true);
        // plugin.getAutoLoginProviderId() defaults to null -> feature off

        extension.handle(data, guestUser, plugin);

        verify(response, never()).sendRedirect(anyString());
        verify(response, never()).addCookie(any(Cookie.class));
    }

    // ---- execute() robustness ------------------------------------------------------------------

    @Test
    public void returnsQuietlyWhenRunDataAbsent() {
        extension.execute(new HashMap<>());

        verifyNoInteractions(data, session, request, response, plugin);
    }

    @Test
    public void executeDoesNotPropagateFailures() {
        // If the internal lookups fail (e.g. no XNAT runtime), execute() must swallow so the page still renders.
        final OpenIdLoginExtension broken = new OpenIdLoginExtension() {
            @Override String fullServerPath() { return SERVER; }
            @Override UserI resolveCurrentUser() { return null; }
            @Override OpenIdAuthPlugin resolvePlugin() { throw new RuntimeException("no context"); }
        };
        final Map<String, Object> params = new HashMap<>();
        params.put("data", data);

        broken.execute(params); // must not throw
    }
}

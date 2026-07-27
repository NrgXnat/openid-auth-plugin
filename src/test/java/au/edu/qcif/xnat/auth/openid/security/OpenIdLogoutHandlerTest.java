package au.edu.qcif.xnat.auth.openid.security;

import au.edu.qcif.xnat.auth.openid.OpenIdAuthPlugin;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import static au.edu.qcif.xnat.auth.openid.OpenIdConnectFilter.AUTO_LOGIN_SUPPRESS_COOKIE;
import static au.edu.qcif.xnat.auth.openid.OpenIdConnectFilter.ID_TOKEN_SESSION_ATTR;
import static au.edu.qcif.xnat.auth.openid.etc.OpenIdAuthConstant.LOGOUT_URI;
import static org.junit.Assert.assertEquals;
import static org.mockito.Mockito.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@RunWith(MockitoJUnitRunner.class)
public class OpenIdLogoutHandlerTest {

    @Mock private OpenIdAuthPlugin    plugin;
    @Mock private HttpServletRequest  request;
    @Mock private HttpServletResponse response;
    @Mock private HttpSession         session;

    @Test
    public void unifiedLogoutCapturesIdTokenAndSetsNoCookie() {
        when(plugin.getAutoLoginProviderId()).thenReturn("keycloak");
        when(plugin.getProperty("keycloak", LOGOUT_URI)).thenReturn("https://kc.example/realms/scout/protocol/openid-connect/logout");
        when(request.getSession(false)).thenReturn(session);
        when(session.getAttribute(ID_TOKEN_SESSION_ATTR)).thenReturn("the-id-token");

        new OpenIdLogoutHandler(plugin).logout(request, response, null);

        verify(request).setAttribute(OpenIdLogoutHandler.ID_TOKEN_HINT_ATTRIBUTE, "the-id-token");
        verify(response, never()).addCookie(any());
    }

    @Test
    public void unifiedLogoutOnTimeoutCapturesNothingAndSetsNoCookie() {
        // logoutUri is set but the session (and its id_token) is already gone — an idle timeout. There's nothing
        // to capture, and we set no suppression cookie: the success handler still makes a best-effort redirect
        // to logoutUri, and a cookie here would wrongly block auto-login after the user next signs in.
        when(plugin.getAutoLoginProviderId()).thenReturn("keycloak");
        when(plugin.getProperty("keycloak", LOGOUT_URI)).thenReturn("https://op.example/logout");
        when(request.getSession(false)).thenReturn(null);

        new OpenIdLogoutHandler(plugin).logout(request, response, null);

        verify(response, never()).addCookie(any());
        verify(request, never()).setAttribute(any(), any());
    }

    @Test
    public void localLogoutSetsCookieAndCapturesNoIdToken() {
        when(plugin.getAutoLoginProviderId()).thenReturn("keycloak");
        // No logoutUri configured -> local logout -> suppression cookie, no id_token capture.

        new OpenIdLogoutHandler(plugin).logout(request, response, null);

        final ArgumentCaptor<Cookie> captor = ArgumentCaptor.forClass(Cookie.class);
        verify(response).addCookie(captor.capture());
        assertEquals(AUTO_LOGIN_SUPPRESS_COOKIE, captor.getValue().getName());
        assertEquals("1", captor.getValue().getValue());
        verify(request, never()).setAttribute(any(), any());
    }

    @Test
    public void doesNothingWhenAutoLoginDisabled() {
        when(plugin.getAutoLoginProviderId()).thenReturn(null);

        new OpenIdLogoutHandler(plugin).logout(request, response, null);

        verify(response, never()).addCookie(any());
        verify(request, never()).setAttribute(any(), any());
    }
}

package au.edu.qcif.xnat.auth.openid.security;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@RunWith(MockitoJUnitRunner.class)
public class RpInitiatedLogoutSuccessHandlerTest {

    private static final String END_SESSION = "https://op.example/realms/scout/protocol/openid-connect/logout";
    private static final String SERVER      = "https://xnat.example";
    private static final String LOGIN_VM    = SERVER + "/app/template/Login.vm";

    @Mock private HttpServletRequest  request;
    @Mock private HttpServletResponse response;

    private RpInitiatedLogoutSuccessHandler handler(final String endSession) {
        return new RpInitiatedLogoutSuccessHandler(endSession, "xnat") {
            @Override String fullServerPath() { return SERVER; }
        };
    }

    @Test
    public void withIdTokenHintRedirectsToProviderEndSession() throws Exception {
        when(request.getAttribute(OpenIdLogoutHandler.ID_TOKEN_HINT_ATTRIBUTE)).thenReturn("the-id-token");

        handler(END_SESSION).onLogoutSuccess(request, response, null);

        final ArgumentCaptor<String> url = ArgumentCaptor.forClass(String.class);
        verify(response).sendRedirect(url.capture());
        assertTrue(url.getValue().startsWith(END_SESSION + "?"));
        assertTrue(url.getValue().contains("id_token_hint=the-id-token"));
        assertTrue(url.getValue().contains("post_logout_redirect_uri=https%3A%2F%2Fxnat.example%2Fapp%2Ftemplate%2FLogin.vm"));
        assertTrue(url.getValue().contains("client_id=xnat"));
    }

    @Test
    public void withoutIdTokenHintStillRedirectsToProviderOmittingHint() throws Exception {
        // Idle timeout / non-OIDC user: no id_token. Best-effort logout — still redirect to the end-session
        // endpoint, just without the hint (the provider decides whether to prompt for confirmation).
        handler(END_SESSION).onLogoutSuccess(request, response, null);

        final ArgumentCaptor<String> url = ArgumentCaptor.forClass(String.class);
        verify(response).sendRedirect(url.capture());
        assertTrue("still goes to the provider end-session endpoint", url.getValue().startsWith(END_SESSION + "?"));
        assertFalse("no id_token_hint when none was captured", url.getValue().contains("id_token_hint"));
        assertTrue(url.getValue().contains("post_logout_redirect_uri="));
    }

    @Test
    public void appendsToExistingQueryStringWithAmpersand() throws Exception {
        final String url = handler(END_SESSION + "?foo=bar").buildEndSessionUrl(LOGIN_VM, "the-id-token");

        assertTrue("must use & when the endpoint already has a query", url.contains("?foo=bar&id_token_hint="));
        assertEquals("no double separators", url.indexOf('?'), url.lastIndexOf('?'));
    }
}

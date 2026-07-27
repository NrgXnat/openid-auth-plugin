package au.edu.qcif.xnat.auth.openid.security;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;
import org.nrg.xnat.utils.InteractiveAgentDetector;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@RunWith(MockitoJUnitRunner.class)
public class LogoutRedirectInvalidSessionStrategyTest {

    @Mock private HttpServletRequest         request;
    @Mock private HttpServletResponse        response;
    @Mock private InteractiveAgentDetector   detector;

    private LogoutRedirectInvalidSessionStrategy withDetector(final InteractiveAgentDetector d) {
        return new LogoutRedirectInvalidSessionStrategy() {
            @Override InteractiveAgentDetector resolveDetector() { return d; }
        };
    }

    @Test
    public void browserRequestIsRoutedToLogout() throws Exception {
        // A browser AJAX call to a data path: the naive "Accept: text/html" heuristic would wrongly 401 it,
        // but the detector recognises the browser as interactive, so it's routed to logout like any navigation.
        when(detector.isDataPath(request)).thenReturn(true);
        when(detector.isInteractiveAgent(request)).thenReturn(true);
        when(request.getContextPath()).thenReturn("");

        withDetector(detector).onInvalidSessionDetected(request, response);

        verify(response).sendRedirect("/app/action/LogoutUser");
    }

    @Test
    public void nonInteractiveDataPathGetsUnauthorized() throws Exception {
        when(detector.isDataPath(request)).thenReturn(true);
        when(detector.isInteractiveAgent(request)).thenReturn(false);

        withDetector(detector).onInvalidSessionDetected(request, response);

        verify(response).sendError(HttpServletResponse.SC_UNAUTHORIZED);
    }

    @Test
    public void fallsBackToAcceptHeaderWhenDetectorUnavailable() throws Exception {
        when(request.getHeader("Accept")).thenReturn("text/html,application/xhtml+xml");
        when(request.getContextPath()).thenReturn("");

        withDetector(null).onInvalidSessionDetected(request, response);

        verify(response).sendRedirect("/app/action/LogoutUser");
    }
}

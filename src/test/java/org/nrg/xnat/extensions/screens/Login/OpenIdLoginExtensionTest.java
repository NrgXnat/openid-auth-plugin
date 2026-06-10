package org.nrg.xnat.extensions.screens.Login;

import org.apache.turbine.util.RunData;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;

import javax.servlet.http.HttpSession;
import java.util.HashMap;
import java.util.Map;

import static au.edu.qcif.xnat.auth.openid.OpenIdConnectFilter.OPENID_ERROR_MESSAGE;
import static org.mockito.Mockito.*;

/**
 * Unit tests for {@link OpenIdLoginExtension}. The extension only manipulates the Turbine
 * {@link RunData} / {@link HttpSession}, both of which are mocked here, so no servlet container or
 * XNAT runtime is required.
 */
@RunWith(MockitoJUnitRunner.class)
public class OpenIdLoginExtensionTest {

    @Mock
    private RunData data;

    @Mock
    private HttpSession session;

    private OpenIdLoginExtension extension;

    @Before
    public void setUp() {
        extension = new OpenIdLoginExtension();
    }

    private Map<String, Object> paramsWithData() {
        final Map<String, Object> params = new HashMap<>();
        params.put("data", data);
        return params;
    }

    @Test
    public void displaysAndClearsErrorMessageWhenPresent() {
        when(data.getSession()).thenReturn(session);
        when(session.getAttribute(OPENID_ERROR_MESSAGE)).thenReturn("Your email domain is not permitted");

        extension.execute(paramsWithData());

        verify(data).setMessage("Your email domain is not permitted");
        // The one-shot message is removed so it does not reappear on the next page load.
        verify(session).removeAttribute(OPENID_ERROR_MESSAGE);
    }

    @Test
    public void doesNothingWhenNoErrorMessage() {
        when(data.getSession()).thenReturn(session);
        when(session.getAttribute(OPENID_ERROR_MESSAGE)).thenReturn(null);

        extension.execute(paramsWithData());

        verify(data, never()).setMessage(anyString());
        verify(session, never()).removeAttribute(anyString());
    }

    @Test
    public void doesNothingWhenErrorMessageIsBlank() {
        when(data.getSession()).thenReturn(session);
        when(session.getAttribute(OPENID_ERROR_MESSAGE)).thenReturn("   ");

        extension.execute(paramsWithData());

        verify(data, never()).setMessage(anyString());
        verify(session, never()).removeAttribute(anyString());
    }

    @Test
    public void returnsQuietlyWhenRunDataAbsent() {
        // No "data" entry -> the extension must short-circuit without touching anything or throwing.
        extension.execute(new HashMap<>());

        verifyNoInteractions(data, session);
    }

    @Test
    public void swallowsExceptionsRaisedWhileReadingSession() {
        when(data.getSession()).thenThrow(new IllegalStateException("session unavailable"));

        // Must not propagate; the login page should still render.
        extension.execute(paramsWithData());

        verify(data, never()).setMessage(anyString());
    }
}

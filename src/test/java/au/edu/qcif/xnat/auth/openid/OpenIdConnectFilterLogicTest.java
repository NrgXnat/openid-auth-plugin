package au.edu.qcif.xnat.auth.openid;

import au.edu.qcif.xnat.auth.openid.service.KeystoreService;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;
import org.nrg.xdat.preferences.SiteConfigPreferences;
import org.nrg.xdat.services.XdatUserAuthService;
import org.springframework.security.authentication.AuthenticationEventPublisher;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.CredentialsExpiredException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.lang.reflect.Method;
import java.util.Collections;
import java.util.Map;
import java.util.Optional;

import static org.junit.Assert.*;
import static org.mockito.Mockito.any;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit tests for the pure decision logic in {@link OpenIdConnectFilter}: the login-page
 * error-message mapping and ID-token encryption detection. (Email-domain whitelisting and the
 * email-verification requirement now live in {@link OpenIdAccountPolicy} and are tested in
 * {@code OpenIdAccountPolicyTest}.)
 *
 * <p>These paths need no OAuth2 exchange, database, or servlet container. The filter is constructed
 * directly with mocked collaborators (only {@link OpenIdAuthPlugin} drives these branches), and the
 * package-private/private methods are exercised via reflection — the same approach used for the PKCE
 * provider's parameter builder. The static-XNAT-dependent paths (user creation, redirects) are
 * deliberately left to integration testing.</p>
 */
@RunWith(MockitoJUnitRunner.class)
public class OpenIdConnectFilterLogicTest {

    private static final String PROVIDER = "keycloak";

    @Mock private OpenIdAuthPlugin               plugin;
    @Mock private AuthenticationEventPublisher   eventPublisher;
    @Mock private XdatUserAuthService            userAuthService;
    @Mock private SiteConfigPreferences          siteConfigPreferences;
    @Mock private KeystoreService                keystoreService;

    /**
     * Builds a filter with {@code PROVIDER} enabled and the given provider properties stubbed. The
     * filter's constructor reads these to build its allowed-domain map, so all stubbing must happen
     * before construction.
     */
    private OpenIdConnectFilter filterWith(final Map<String, String> providerProps) {
        lenient().when(plugin.getRedirectUri()).thenReturn("/openid/callback");
        lenient().when(plugin.getEnabledProviders()).thenReturn(Collections.singletonList(PROVIDER));
        providerProps.forEach((key, value) -> lenient().when(plugin.getProperty(PROVIDER, key)).thenReturn(value));
        return new OpenIdConnectFilter(plugin, eventPublisher, userAuthService, siteConfigPreferences, keystoreService);
    }

    private static boolean isIdTokenEncrypted(final OpenIdConnectFilter filter, final String idToken) throws Exception {
        final Method method = OpenIdConnectFilter.class.getDeclaredMethod("isIdTokenEncrypted", String.class);
        method.setAccessible(true);
        return (boolean) method.invoke(filter, idToken);
    }

    private static String getUserMessage(final AuthenticationException failed) throws Exception {
        final Method method = OpenIdConnectFilter.class.getDeclaredMethod("getUserMessage", AuthenticationException.class);
        method.setAccessible(true);
        return (String) method.invoke(null, failed);
    }

    // ---- login-page error messages -------------------------------------------------------------

    @Test
    public void usernamePatternFailureYieldsConfigurationErrorMessage() throws Exception {
        final String message = getUserMessage(new BadCredentialsException(
                "Cannot resolve username pattern: please check your usernamePattern configuration"));

        assertTrue(message.toLowerCase().contains("configuration error"));
    }

    @Test
    public void genericBadCredentialsYieldsRetryMessage() throws Exception {
        final String message = getUserMessage(new BadCredentialsException("Could not obtain access token"));

        assertTrue(message.contains("Please try again"));
        assertFalse("generic failures must not leak the config-error wording", message.toLowerCase().contains("configuration error"));
    }

    @Test
    public void nonBadCredentialsExceptionYieldsRetryMessage() throws Exception {
        final String message = getUserMessage(new CredentialsExpiredException("Attempted login to locked account: jdoe"));

        assertTrue(message.contains("Please try again"));
    }

    // ---- ID token encryption detection ---------------------------------------------------------

    @Test
    public void fivePartTokenIsDetectedAsEncrypted() throws Exception {
        final OpenIdConnectFilter filter = filterWith(Collections.emptyMap());

        // A JWE compact serialization has five dot-separated parts.
        assertTrue(isIdTokenEncrypted(filter, "header.encKey.iv.ciphertext.tag"));
    }

    @Test
    public void threePartTokenIsNotEncrypted() throws Exception {
        final OpenIdConnectFilter filter = filterWith(Collections.emptyMap());

        // A signed JWT (JWS) has three dot-separated parts.
        assertFalse(isIdTokenEncrypted(filter, "header.payload.signature"));
    }

    // ---- auto-login error handling -------------------------------------------------------------

    @Test
    public void interactionRequiredErrorsAreRecognised() {
        assertTrue(OpenIdConnectFilter.isInteractionRequiredError("login_required"));
        assertTrue(OpenIdConnectFilter.isInteractionRequiredError("interaction_required"));
        assertTrue(OpenIdConnectFilter.isInteractionRequiredError("consent_required"));
        assertTrue(OpenIdConnectFilter.isInteractionRequiredError("account_selection_required"));
        assertFalse(OpenIdConnectFilter.isInteractionRequiredError("access_denied"));
        assertFalse(OpenIdConnectFilter.isInteractionRequiredError(null));
        assertFalse(OpenIdConnectFilter.isInteractionRequiredError(""));
    }

    @Test(expected = BadCredentialsException.class)
    public void nonInteractionRequiredErrorIsTreatedAsFailure() throws Exception {
        final OpenIdConnectFilter filter = filterWith(Collections.emptyMap());
        final HttpServletRequest request = mock(HttpServletRequest.class);
        final HttpServletResponse response = mock(HttpServletResponse.class);
        when(request.getParameter("error")).thenReturn("access_denied");

        // A non-interaction-required error (e.g. access_denied) is a genuine credential failure, not an
        // expected auto-login fallback, so it surfaces as an exception.
        filter.attemptAuthentication(request, response);
    }

    @Test
    public void clearsAutoLoginSuppressionCookieWhenPresent() {
        final HttpServletRequest request = mock(HttpServletRequest.class);
        final HttpServletResponse response = mock(HttpServletResponse.class);
        when(request.getCookies()).thenReturn(new Cookie[]{new Cookie(OpenIdConnectFilter.AUTO_LOGIN_SUPPRESS_COOKIE, "1")});
        when(request.isSecure()).thenReturn(true);

        OpenIdConnectFilter.clearAutoLoginSuppressionCookie(request, response);

        final ArgumentCaptor<Cookie> captor = ArgumentCaptor.forClass(Cookie.class);
        verify(response).addCookie(captor.capture());
        assertEquals(OpenIdConnectFilter.AUTO_LOGIN_SUPPRESS_COOKIE, captor.getValue().getName());
        assertEquals("expiring the cookie", 0, captor.getValue().getMaxAge());
    }

    @Test
    public void clearAutoLoginSuppressionCookieIsNoOpWhenAbsent() {
        final HttpServletRequest request = mock(HttpServletRequest.class);
        final HttpServletResponse response = mock(HttpServletResponse.class);
        when(request.getCookies()).thenReturn(null);

        OpenIdConnectFilter.clearAutoLoginSuppressionCookie(request, response);

        verify(response, never()).addCookie(any());
    }
}

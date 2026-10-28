package au.edu.qcif.xnat.auth.openid;

import au.edu.qcif.xnat.auth.openid.jwt.JwtValidatorRegistry;
import au.edu.qcif.xnat.auth.openid.service.KeystoreService;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;
import org.nrg.xdat.preferences.SiteConfigPreferences;
import org.nrg.xdat.services.XdatUserAuthService;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.authentication.AuthenticationEventPublisher;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.CredentialsExpiredException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;
import org.springframework.security.oauth2.client.resource.UserRedirectRequiredException;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.SavedRequest;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.lang.reflect.Method;
import java.util.Collections;
import java.util.Properties;
import java.util.Map;
import java.util.Optional;

import static org.junit.Assert.*;
import static org.mockito.Mockito.any;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link OpenIdConnectFilter} branches that need no token exchange, database, or servlet container.
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
        lenient().when(plugin.getProps()).thenReturn(new Properties());
        lenient().when(plugin.getEnabledProviders()).thenReturn(Collections.singletonList(PROVIDER));
        providerProps.forEach((key, value) -> lenient().when(plugin.getProperty(PROVIDER, key)).thenReturn(value));
        return new OpenIdConnectFilter(plugin, eventPublisher, userAuthService, siteConfigPreferences, keystoreService, new JwtValidatorRegistry(plugin), Runnable::run);
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

    // ---- provider resolution on the callback ---------------------------------------------------

    @Test(expected = BadCredentialsException.class)
    public void failsWhenNoProviderCanBeDeterminedForTheRequest() throws Exception {
        final OpenIdConnectFilter filter = filterWith(Collections.emptyMap());
        final HttpServletRequest request = mock(HttpServletRequest.class);
        final HttpServletResponse response = mock(HttpServletResponse.class);
        // A callback with no ?providerId and no session: the sign-in never started here, which is what a
        // callback landing on a different host than the outbound request looks like. Without this the
        // token exchange is attempted against a provider whose endpoints are all null, and the request
        // stalls with nothing logged.
        when(request.getParameter("providerId")).thenReturn(null);
        when(request.getSession(false)).thenReturn(null);

        filter.attemptAuthentication(request, response);
    }

    @Test(expected = BadCredentialsException.class)
    public void failsWhenTheSessionExistsButNeverRecordedAProvider() throws Exception {
        final OpenIdConnectFilter filter = filterWith(Collections.emptyMap());
        final HttpServletRequest request = mock(HttpServletRequest.class);
        final HttpServletResponse response = mock(HttpServletResponse.class);
        final HttpSession session = mock(HttpSession.class);
        when(request.getParameter("providerId")).thenReturn(null);
        when(request.getSession(false)).thenReturn(session);
        when(session.getAttribute("providerId")).thenReturn(null);

        filter.attemptAuthentication(request, response);
    }

    @Test
    public void clearsAutoLoginCookiesWhenPresent() {
        final HttpServletRequest request = mock(HttpServletRequest.class);
        final HttpServletResponse response = mock(HttpServletResponse.class);
        when(request.getCookies()).thenReturn(new Cookie[]{
                new Cookie(OpenIdConnectFilter.AUTO_LOGIN_SUPPRESS_COOKIE, "1"),
                new Cookie(OpenIdConnectFilter.AUTO_LOGIN_ATTEMPTED_COOKIE, "1"),
                new Cookie("JSESSIONID", "abc")});
        when(request.isSecure()).thenReturn(true);

        OpenIdConnectFilter.clearAutoLoginCookies(request, response);

        final ArgumentCaptor<Cookie> captor = ArgumentCaptor.forClass(Cookie.class);
        verify(response, times(2)).addCookie(captor.capture());
        assertEquals(OpenIdConnectFilter.AUTO_LOGIN_SUPPRESS_COOKIE, captor.getAllValues().get(0).getName());
        assertEquals(OpenIdConnectFilter.AUTO_LOGIN_ATTEMPTED_COOKIE, captor.getAllValues().get(1).getName());
        captor.getAllValues().forEach(cookie -> assertEquals("expiring the cookie", 0, cookie.getMaxAge()));
    }

    @Test
    public void clearAutoLoginCookiesIsNoOpWhenAbsent() {
        final HttpServletRequest request = mock(HttpServletRequest.class);
        final HttpServletResponse response = mock(HttpServletResponse.class);
        when(request.getCookies()).thenReturn(null);

        OpenIdConnectFilter.clearAutoLoginCookies(request, response);

        verify(response, never()).addCookie(any());
    }

    // ---- pre-login session when starting a login -----------------------------------------------

    @Test
    public void keepsTheSessionWhenStartingALogin() throws Exception {
        final MockHttpSession original = sessionWithRequestedPage();
        original.setAttribute("par", "invitation");

        final MockHttpServletRequest request = startLogin(original);

        assertFalse(original.isInvalid());
        assertEquals("http://localhost" + REQUESTED_PAGE, savedRequestIn(request).getRedirectUrl());
        assertEquals("invitation", request.getSession().getAttribute("par"));
    }

    @Test
    public void discardsASessionLeftOverFromAnotherProvidersLogin() throws Exception {
        final MockHttpSession original = sessionWithRequestedPage();
        original.setAttribute("providerId", "other");

        startLogin(original);

        assertTrue(original.isInvalid());
    }

    private static final String REQUESTED_PAGE = "/app/template/XDATScreen_add_xnat_projectData.vm";

    /** A session holding what Spring saves before sending an anonymous visitor to the login page. */
    private static MockHttpSession sessionWithRequestedPage() {
        final MockHttpSession session = new MockHttpSession();
        final MockHttpServletRequest deepLink = new MockHttpServletRequest("GET", REQUESTED_PAGE);
        deepLink.setSession(session);
        new HttpSessionRequestCache().saveRequest(deepLink, new MockHttpServletResponse());
        return session;
    }

    /** Requests {@code /openid-login?providerId=PROVIDER} in the given session, up to the redirect to the provider. */
    private MockHttpServletRequest startLogin(final MockHttpSession session) throws Exception {
        final OpenIdConnectFilter filter = filterWith(Collections.emptyMap());
        final OAuth2RestTemplate restTemplate = mock(OAuth2RestTemplate.class);
        when(restTemplate.getAccessToken()).thenThrow(new UserRedirectRequiredException("https://idp.example/auth", Collections.emptyMap()));
        filter.setOAuth2RestTemplate(restTemplate);

        final MockHttpServletRequest request = new MockHttpServletRequest("GET", "/openid-login");
        request.setParameter("providerId", PROVIDER);
        request.setSession(session);
        try {
            filter.attemptAuthentication(request, new MockHttpServletResponse());
            fail("expected a redirect to the provider");
        } catch (final UserRedirectRequiredException expected) {
            // the outbound leg of the login ends here
        }
        return request;
    }

    private static SavedRequest savedRequestIn(final MockHttpServletRequest request) {
        return new HttpSessionRequestCache().getRequest(request, new MockHttpServletResponse());
    }
}

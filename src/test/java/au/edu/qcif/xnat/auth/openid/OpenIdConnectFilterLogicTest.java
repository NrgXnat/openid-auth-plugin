package au.edu.qcif.xnat.auth.openid;

import au.edu.qcif.xnat.auth.openid.service.KeystoreService;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;
import org.nrg.xdat.preferences.SiteConfigPreferences;
import org.nrg.xdat.services.XdatUserAuthService;
import org.springframework.security.authentication.AuthenticationEventPublisher;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.CredentialsExpiredException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

import java.lang.reflect.Method;
import java.util.Collections;
import java.util.Map;
import java.util.Optional;

import static org.junit.Assert.*;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
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
        return new OpenIdConnectFilter(Optional.of(mock(AuthenticationSuccessHandler.class)),plugin, eventPublisher, userAuthService, siteConfigPreferences, keystoreService);
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
}

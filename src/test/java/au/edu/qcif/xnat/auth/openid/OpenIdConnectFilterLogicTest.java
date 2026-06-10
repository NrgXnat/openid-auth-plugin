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

import java.lang.reflect.Method;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import static org.junit.Assert.*;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.when;

/**
 * Unit tests for the pure decision logic in {@link OpenIdConnectFilter}: email-domain whitelisting,
 * the login-page error-message mapping, and ID-token encryption detection.
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

    private static Map<String, String> filteringOn(final String allowedEmailDomains) {
        final Map<String, String> props = new HashMap<>();
        props.put("shouldFilterEmailDomains", "true");
        props.put("allowedEmailDomains", allowedEmailDomains);
        return props;
    }

    private static boolean isAllowedEmailDomain(final OpenIdConnectFilter filter, final String email, final String providerId) throws Exception {
        final Method method = OpenIdConnectFilter.class.getDeclaredMethod("isAllowedEmailDomain", String.class, String.class);
        method.setAccessible(true);
        return (boolean) method.invoke(filter, email, providerId);
    }

    private static boolean shouldFilterEmailDomains(final OpenIdConnectFilter filter, final String providerId) throws Exception {
        final Method method = OpenIdConnectFilter.class.getDeclaredMethod("shouldFilterEmailDomains", String.class);
        method.setAccessible(true);
        return (boolean) method.invoke(filter, providerId);
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

    // ---- email-domain whitelisting -------------------------------------------------------------

    @Test
    public void anyDomainAllowedWhenFilteringDisabled() throws Exception {
        final OpenIdConnectFilter filter = filterWith(Collections.singletonMap("shouldFilterEmailDomains", "false"));

        assertTrue(isAllowedEmailDomain(filter, "anyone@whatever.example", PROVIDER));
    }

    @Test
    public void domainOnWhitelistIsAllowed() throws Exception {
        final OpenIdConnectFilter filter = filterWith(filteringOn("example.org, wustl.edu"));

        assertTrue(isAllowedEmailDomain(filter, "jane@wustl.edu", PROVIDER));
    }

    @Test
    public void domainNotOnWhitelistIsRejected() throws Exception {
        final OpenIdConnectFilter filter = filterWith(filteringOn("example.org, wustl.edu"));

        assertFalse(isAllowedEmailDomain(filter, "jane@gmail.com", PROVIDER));
    }

    @Test
    public void whitelistMatchIsCaseInsensitive() throws Exception {
        final OpenIdConnectFilter filter = filterWith(filteringOn("wustl.edu"));

        assertTrue(isAllowedEmailDomain(filter, "Jane@WUSTL.EDU", PROVIDER));
    }

    @Test
    public void wildcardWhitelistAllowsAnyDomain() throws Exception {
        final OpenIdConnectFilter filter = filterWith(filteringOn("*"));

        assertTrue(isAllowedEmailDomain(filter, "jane@anything.example", PROVIDER));
    }

    @Test
    public void malformedEmailWithoutDomainIsRejected() throws Exception {
        final OpenIdConnectFilter filter = filterWith(filteringOn("wustl.edu"));

        assertFalse("an address with no @ has no parseable domain", isAllowedEmailDomain(filter, "not-an-email", PROVIDER));
    }

    @Test
    public void unknownProviderIsRejected() throws Exception {
        // Only PROVIDER is enabled; a different provider id is absent from the allowed-domains map.
        final OpenIdConnectFilter filter = filterWith(filteringOn("wustl.edu"));

        assertFalse(isAllowedEmailDomain(filter, "jane@wustl.edu", "some-other-provider"));
    }

    @Test
    public void shouldFilterEmailDomainsDefaultsToFalseWhenUnset() throws Exception {
        // Property not stubbed -> null -> defaults to "false".
        final OpenIdConnectFilter filter = filterWith(Collections.emptyMap());

        assertFalse(shouldFilterEmailDomains(filter, PROVIDER));
    }

    @Test
    public void shouldFilterEmailDomainsReflectsConfiguredValue() throws Exception {
        final OpenIdConnectFilter filter = filterWith(filteringOn("wustl.edu"));

        assertTrue(shouldFilterEmailDomains(filter, PROVIDER));
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

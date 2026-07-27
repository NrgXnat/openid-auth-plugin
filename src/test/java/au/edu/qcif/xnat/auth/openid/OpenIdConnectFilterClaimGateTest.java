package au.edu.qcif.xnat.auth.openid;

import au.edu.qcif.xnat.auth.openid.gate.TokenContext;
import au.edu.qcif.xnat.auth.openid.service.KeystoreService;
import com.nimbusds.jwt.JWTClaimsSet;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;
import org.nrg.xdat.preferences.SiteConfigPreferences;
import org.nrg.xdat.services.XdatUserAuthService;
import org.springframework.security.authentication.AuthenticationEventPublisher;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;

/**
 * Unit tests for the ID-token claim-gate wiring in {@link OpenIdConnectFilter}: the filter runs the
 * enabled gates against the parsed {@link JWTClaimsSet} and, on a gate failure, raises a
 * {@link BadCredentialsException} (the interactive path's existing validation-failure handling,
 * since the status code is invisible behind a login redirect).
 *
 * <p>Built directly with mocked collaborators and exercised via reflection, in the same style as
 * {@link OpenIdConnectFilterLogicTest}.</p>
 */
@RunWith(MockitoJUnitRunner.class)
public class OpenIdConnectFilterClaimGateTest {

    private static final String PROVIDER = "keycloak";

    @Mock private OpenIdAuthPlugin             plugin;
    @Mock private AuthenticationEventPublisher eventPublisher;
    @Mock private XdatUserAuthService          userAuthService;
    @Mock private SiteConfigPreferences        siteConfigPreferences;
    @Mock private KeystoreService              keystoreService;

    private OpenIdConnectFilter filterWith(final Map<String, String> providerProps) {
        lenient().when(plugin.getRedirectUri()).thenReturn("/openid/callback");
        lenient().when(plugin.getEnabledProviders()).thenReturn(Collections.singletonList(PROVIDER));
        providerProps.forEach((key, value) -> lenient().when(plugin.getProperty(PROVIDER, key)).thenReturn(value));
        return new OpenIdConnectFilter(Optional.of(mock(AuthenticationSuccessHandler.class)),plugin, eventPublisher, userAuthService, siteConfigPreferences, keystoreService);
    }

    private static void applyIdTokenClaimGates(final OpenIdConnectFilter filter, final String providerId,
                                               final JWTClaimsSet claims) throws Exception {
        final Method method = OpenIdConnectFilter.class.getDeclaredMethod(
                "applyIdTokenClaimGates", String.class, TokenContext.class);
        method.setAccessible(true);
        try {
            method.invoke(filter, providerId, TokenContext.of(claims));
        } catch (InvocationTargetException e) {
            // Unwrap so callers can assert on the real cause (e.g. BadCredentialsException).
            if (e.getCause() instanceof Exception) {
                throw (Exception) e.getCause();
            }
            throw e;
        }
    }

    private static Map<String, String> roleGateOn() {
        final Map<String, String> props = new HashMap<>();
        props.put("roleCheck.rolePath", "resource_access.xnat.roles");
        props.put("roleCheck.requiredRoles", "xnat_access");
        props.put("idToken.roleCheck.enabled", "true");
        return props;
    }

    private static JWTClaimsSet claimsWithRoles(final String... roles) {
        final Map<String, Object> xnat = new HashMap<>();
        xnat.put("roles", Arrays.asList(roles));
        final Map<String, Object> resourceAccess = new HashMap<>();
        resourceAccess.put("xnat", xnat);
        return new JWTClaimsSet.Builder().claim("resource_access", resourceAccess).build();
    }

    @Test
    public void passesWhenEnabledGateIsSatisfied() throws Exception {
        final OpenIdConnectFilter filter = filterWith(roleGateOn());

        // No exception expected.
        applyIdTokenClaimGates(filter, PROVIDER, claimsWithRoles("xnat_access"));
    }

    @Test
    public void failedGateRaisesBadCredentials() throws Exception {
        final OpenIdConnectFilter filter = filterWith(roleGateOn());

        try {
            applyIdTokenClaimGates(filter, PROVIDER, claimsWithRoles("guest"));
            fail("expected BadCredentialsException");
        } catch (BadCredentialsException expected) {
            assertTrue(expected.getMessage().contains("xnat_access"));
        }
    }

    @Test
    public void noGatesConfiguredAllowsAnyClaims() throws Exception {
        // No gate properties stubbed -> all toggles default false -> no gate runs.
        final OpenIdConnectFilter filter = filterWith(Collections.emptyMap());

        applyIdTokenClaimGates(filter, PROVIDER, claimsWithRoles("anything"));
    }
}

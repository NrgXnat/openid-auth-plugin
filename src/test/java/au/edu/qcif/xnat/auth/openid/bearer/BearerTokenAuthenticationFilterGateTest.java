package au.edu.qcif.xnat.auth.openid.bearer;

import au.edu.qcif.xnat.auth.openid.OpenIdAuthPlugin;
import au.edu.qcif.xnat.auth.openid.gate.ClaimGateException;
import au.edu.qcif.xnat.auth.openid.gate.ClaimGateFactory;
import com.nimbusds.jwt.JWTClaimsSet;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import static org.mockito.Mockito.lenient;

/**
 * Unit tests for the bearer-path claim-gate wiring in {@link BearerTokenAuthenticationFilter}: the
 * filter runs the gates enabled for {@code AuthPath.BEARER} against the validated {@link JWTClaimsSet}
 * and, on a gate failure, raises a {@link ClaimGateException} (which {@code doFilterInternal} maps to
 * 403). Mirrors {@code OpenIdConnectFilterClaimGateTest}, exercising the package-private method via
 * reflection with mocked collaborators.
 */
@RunWith(MockitoJUnitRunner.class)
public class BearerTokenAuthenticationFilterGateTest {

    private static final String PROVIDER = "keycloak";

    @Mock private OpenIdAuthPlugin plugin;

    private BearerTokenAuthenticationFilter filterWith(final Map<String, String> providerProps) {
        providerProps.forEach((key, value) -> lenient().when(plugin.getProperty(PROVIDER, key)).thenReturn(value));
        // Only the gate factory matters here; the other collaborators are unused by applyBearerClaimGates.
        return new BearerTokenAuthenticationFilter(plugin, new BearerTokenExtractor(), null,
                Collections.emptyMap(), new ClaimGateFactory(plugin), null);
    }

    private static void applyBearerClaimGates(final BearerTokenAuthenticationFilter filter, final String providerId,
                                              final JWTClaimsSet claims) throws Exception {
        final Method method = BearerTokenAuthenticationFilter.class.getDeclaredMethod(
                "applyBearerClaimGates", String.class, JWTClaimsSet.class);
        method.setAccessible(true);
        try {
            method.invoke(filter, providerId, claims);
        } catch (InvocationTargetException e) {
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
        props.put("bearer.roleCheck.enabled", "true");
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
        final BearerTokenAuthenticationFilter filter = filterWith(roleGateOn());

        // No exception expected.
        applyBearerClaimGates(filter, PROVIDER, claimsWithRoles("xnat_access"));
    }

    @Test
    public void failedGateThrowsClaimGateException() throws Exception {
        final BearerTokenAuthenticationFilter filter = filterWith(roleGateOn());

        try {
            applyBearerClaimGates(filter, PROVIDER, claimsWithRoles("guest"));
            fail("expected ClaimGateException");
        } catch (ClaimGateException expected) {
            assertTrue(expected.getMessage().contains("xnat_access"));
        }
    }

    @Test
    public void noGatesConfiguredAllowsAnyClaims() throws Exception {
        // No bearer gate toggles stubbed -> gatesFor returns empty -> no gate runs.
        final BearerTokenAuthenticationFilter filter = filterWith(Collections.emptyMap());

        applyBearerClaimGates(filter, PROVIDER, claimsWithRoles("anything"));
    }
}

package au.edu.qcif.xnat.auth.openid.gate;

import au.edu.qcif.xnat.auth.openid.OpenIdAuthPlugin;
import com.nimbusds.jwt.JWTClaimsSet;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;

import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import static org.mockito.Mockito.lenient;

/**
 * Unit tests for {@link ClaimGateFactory}: per-(provider, path) gate assembly from configuration,
 * including the per-path override falling back to the shared per-provider definition, and the
 * default-off behaviour of the enable toggles.
 */
@RunWith(MockitoJUnitRunner.class)
public class ClaimGateFactoryTest {

    private static final String PROVIDER = "wustl";

    @Mock private OpenIdAuthPlugin plugin;

    private final Map<String, String> props = new HashMap<>();

    @Before
    public void stubProperties() {
        // Any property key resolves through this map; absent keys return null (as Properties would).
        lenient().when(plugin.getProperty(org.mockito.ArgumentMatchers.eq(PROVIDER), org.mockito.ArgumentMatchers.anyString()))
                .thenAnswer(invocation -> props.get(invocation.getArgument(1)));
    }

    private ClaimGateFactory factory() {
        return new ClaimGateFactory(plugin);
    }

    // ---- enablement ----------------------------------------------------------------------------

    @Test
    public void noGatesWhenAllTogglesOff() {
        assertTrue(factory().gatesFor(PROVIDER, AuthPath.ID_TOKEN).isEmpty());
        assertTrue(factory().gatesFor(PROVIDER, AuthPath.BEARER).isEmpty());
    }

    @Test
    public void idTokenRoleGateEnabled() {
        props.put("roleCheck.rolePath", "resource_access.xnat.roles");
        props.put("roleCheck.requiredRoles", "xnat_access");
        props.put("idToken.roleCheck.enabled", "true");

        final List<ClaimGate> gates = factory().gatesFor(PROVIDER, AuthPath.ID_TOKEN);

        assertEquals(1, gates.size());
        assertTrue(gates.get(0) instanceof RoleGate);
    }

    @Test
    public void bearerAudGateEnabled() {
        props.put("audCheck.acceptedAudiences", "xnat");
        props.put("bearer.audCheck.enabled", "true");

        final List<ClaimGate> gates = factory().gatesFor(PROVIDER, AuthPath.BEARER);

        assertEquals(1, gates.size());
        assertTrue(gates.get(0) instanceof AudienceGate);
    }

    @Test
    public void bothGatesEnabledOnBearerPath() {
        props.put("audCheck.acceptedAudiences", "xnat");
        props.put("roleCheck.rolePath", "resource_access.xnat.roles");
        props.put("roleCheck.requiredRoles", "xnat_access");
        props.put("bearer.audCheck.enabled", "true");
        props.put("bearer.roleCheck.enabled", "true");

        assertEquals(2, factory().gatesFor(PROVIDER, AuthPath.BEARER).size());
    }

    @Test
    public void enableToggleIsPathSpecific() {
        // Enabled on bearer only; the ID-token path must see no gate.
        props.put("audCheck.acceptedAudiences", "xnat");
        props.put("bearer.audCheck.enabled", "true");

        assertTrue(factory().gatesFor(PROVIDER, AuthPath.ID_TOKEN).isEmpty());
        assertEquals(1, factory().gatesFor(PROVIDER, AuthPath.BEARER).size());
    }

    // ---- per-path override of "what to check" --------------------------------------------------

    @Test
    public void perPathRolePathOverridesSharedDefinition() {
        props.put("roleCheck.rolePath", "resource_access.xnat.roles");
        props.put("roleCheck.requiredRoles", "realm_admin");
        props.put("bearer.roleCheck.rolePath", "realm_access.roles");
        props.put("bearer.roleCheck.enabled", "true");

        final RoleGate gate = (RoleGate) factory().gatesFor(PROVIDER, AuthPath.BEARER).get(0);

        // A token carrying the role under the OVERRIDE path passes; under the shared path it would not.
        try {
            gate.check(realmAccessClaims("realm_admin"));
        } catch (ClaimGateException e) {
            fail("Token should have carried a valid role claim");
        }
        try {
            gate.check(resourceAccessClaims("realm_admin"));
            fail("override path should not read the shared resource_access location");
        } catch (ClaimGateException expected) {
            // pass
        }
    }

    @Test
    public void sharedRolePathUsedWhenNoOverride() {
        props.put("roleCheck.rolePath", "resource_access.xnat.roles");
        props.put("roleCheck.requiredRoles", "xnat_access");
        props.put("idToken.roleCheck.enabled", "true");

        final RoleGate gate = (RoleGate) factory().gatesFor(PROVIDER, AuthPath.ID_TOKEN).get(0);

        try {
            gate.check(resourceAccessClaims("xnat_access")); // throws if the shared path was not used
        } catch (ClaimGateException e) {
            fail("shared path was not used");
        }
    }

    private static JWTClaimsSet resourceAccessClaims(final String... roles) {
        final Map<String, Object> xnat = new HashMap<>();
        xnat.put("roles", Arrays.asList(roles));
        final Map<String, Object> resourceAccess = new HashMap<>();
        resourceAccess.put("xnat", xnat);
        return new JWTClaimsSet.Builder().claim("resource_access", resourceAccess).build();
    }

    private static JWTClaimsSet realmAccessClaims(final String... roles) {
        final Map<String, Object> realmAccess = new HashMap<>();
        realmAccess.put("roles", Arrays.asList(roles));
        return new JWTClaimsSet.Builder().claim("realm_access", realmAccess).build();
    }
}

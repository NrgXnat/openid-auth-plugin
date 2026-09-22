package au.edu.qcif.xnat.auth.openid.gate;

import com.nimbusds.jwt.JWTClaimsSet;
import org.junit.Test;

import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import static org.junit.Assert.fail;

/**
 * Unit tests for {@link RoleGate}: the any-of test over roles read from a configurable nested claim
 * path. A pass is silent; a failure throws {@link ClaimGateException}.
 */
public class RoleGateTest {

    private static final String[] PATH = "resource_access.xnat.roles".split("\\.");

    private static Set<String> requiring(final String... roles) {
        return new HashSet<>(Arrays.asList(roles));
    }

    private static JWTClaimsSet withRoles(final String... roles) {
        final Map<String, Object> xnat = new HashMap<>();
        xnat.put("roles", Arrays.asList(roles));
        final Map<String, Object> resourceAccess = new HashMap<>();
        resourceAccess.put("xnat", xnat);
        return new JWTClaimsSet.Builder().claim("resource_access", resourceAccess).build();
    }

    private static void assertPasses(final RoleGate gate, final JWTClaimsSet claims) {
        try {
            gate.check(TokenContext.of(claims));
        } catch (ClaimGateException e) {
            fail("claims did not pass");
        }
        // throws on failure; reaching here is the pass assertion
    }

    private static void assertRejects(final RoleGate gate, final JWTClaimsSet claims) {
        try {
            gate.check(TokenContext.of(claims));
            fail("expected ClaimGateException");
        } catch (ClaimGateException expected) {
            // pass
        }
    }

    @Test
    public void passesWhenRequiredRolePresent() {
        assertPasses(new RoleGate(PATH, requiring("xnat_access")), withRoles("xnat_access"));
    }

    @Test
    public void passesWhenAnyOfSeveralRequiredRolesPresent() {
        assertPasses(new RoleGate(PATH, requiring("admin", "xnat_access")), withRoles("xnat_access"));
    }

    @Test
    public void rejectsWhenNoRequiredRolePresent() {
        assertRejects(new RoleGate(PATH, requiring("xnat_access")), withRoles("guest"));
    }

    @Test
    public void rejectsWhenRolesClaimAbsent() {
        assertRejects(new RoleGate(PATH, requiring("xnat_access")),
                new JWTClaimsSet.Builder().subject("alice").build());
    }
}

package au.edu.qcif.xnat.auth.openid.gate;

import com.nimbusds.jwt.JWTClaimsSet;
import org.junit.Test;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

/**
 * Unit tests for {@link ClaimPaths}: navigating nested {@code JWTClaimsSet} claims and coercing a
 * leaf claim into a set of roles. These verify the structured-claim handling the role gate depends
 * on, which the flattened {@code Map<String,String>} authInfo cannot provide.
 */
public class ClaimPathsTest {

    /** Builds a claims set whose {@code resource_access} claim mirrors Keycloak's nested shape. */
    private static JWTClaimsSet keycloakClaims(final Object rolesLeaf) {
        final Map<String, Object> xnat = new HashMap<>();
        xnat.put("roles", rolesLeaf);
        final Map<String, Object> resourceAccess = new HashMap<>();
        resourceAccess.put("xnat", xnat);
        return new JWTClaimsSet.Builder().claim("resource_access", resourceAccess).build();
    }

    private static String[] path(final String dotted) {
        return dotted.split("\\.");
    }

    // ---- navigate ------------------------------------------------------------------------------

    @Test
    public void navigateReachesNestedLeaf() {
        final JWTClaimsSet claims = keycloakClaims(Arrays.asList("xnat_access"));

        final Object leaf = ClaimPaths.navigate(claims, path("resource_access.xnat.roles"));

        assertEquals(Arrays.asList("xnat_access"), leaf);
    }

    @Test
    public void navigateReturnsNullWhenSegmentMissing() {
        final JWTClaimsSet claims = keycloakClaims(Arrays.asList("xnat_access"));

        assertNull(ClaimPaths.navigate(claims, path("resource_access.other.roles")));
    }

    @Test
    public void navigateReturnsNullWhenIntermediateIsNotAMap() {
        // resource_access.xnat is a String here, so navigating one level deeper must fail safely.
        final Map<String, Object> resourceAccess = new HashMap<>();
        resourceAccess.put("xnat", "not-a-map");
        final JWTClaimsSet claims = new JWTClaimsSet.Builder().claim("resource_access", resourceAccess).build();

        assertNull(ClaimPaths.navigate(claims, path("resource_access.xnat.roles")));
    }

    @Test
    public void navigateReturnsNullWhenTopLevelClaimAbsent() {
        final JWTClaimsSet claims = new JWTClaimsSet.Builder().subject("alice").build();

        assertNull(ClaimPaths.navigate(claims, path("resource_access.xnat.roles")));
    }

    // ---- extractRoles --------------------------------------------------------------------------

    @Test
    public void extractRolesFromList() {
        final JWTClaimsSet claims = keycloakClaims(Arrays.asList("xnat_access", "admin"));

        final Set<String> roles = ClaimPaths.extractRoles(claims, path("resource_access.xnat.roles"));

        assertEquals(2, roles.size());
        assertTrue(roles.contains("xnat_access"));
        assertTrue(roles.contains("admin"));
    }

    @Test
    public void extractRolesFromSpaceDelimitedString() {
        final JWTClaimsSet claims = keycloakClaims("xnat_access admin");

        final Set<String> roles = ClaimPaths.extractRoles(claims, path("resource_access.xnat.roles"));

        assertEquals(2, roles.size());
        assertTrue(roles.contains("xnat_access"));
        assertTrue(roles.contains("admin"));
    }

    @Test
    public void extractRolesFromArray() {
        final JWTClaimsSet claims = keycloakClaims(new String[]{"xnat_access", "admin"});

        final Set<String> roles = ClaimPaths.extractRoles(claims, path("resource_access.xnat.roles"));

        assertEquals(2, roles.size());
        assertTrue(roles.contains("xnat_access"));
        assertTrue(roles.contains("admin"));
    }

    @Test
    public void extractRolesIsEmptyWhenPathAbsent() {
        final JWTClaimsSet claims = new JWTClaimsSet.Builder().subject("alice").build();

        final Set<String> roles = ClaimPaths.extractRoles(claims, path("resource_access.xnat.roles"));

        assertEquals(Collections.emptySet(), roles);
    }
}

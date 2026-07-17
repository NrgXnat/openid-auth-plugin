package au.edu.qcif.xnat.auth.openid.gate;

import java.util.Arrays;
import java.util.Collections;
import java.util.Set;

/**
 * Passes when the token carries at least one of the configured required roles (an any-of test).
 * Roles are read from a configurable, possibly nested claim path such as Keycloak's
 * {@code resource_access.xnat.roles}.
 */
final class RoleGate implements ClaimGate {

    private final String[] path;
    private final Set<String> requiredRoles;

    RoleGate(final String[] path, final Set<String> requiredRoles) {
        this.path = path;
        this.requiredRoles = requiredRoles;
    }

    @Override
    public void check(final TokenContext token) throws ClaimGateException {
        final Set<String> roles = ClaimPaths.extractRoles(token.claims(), path);
        if (Collections.disjoint(roles, requiredRoles)) {
            throw new ClaimGateException("Token roles " + roles + " at " + Arrays.toString(path)
                    + " contain none of the required roles " + requiredRoles);
        }
    }
}

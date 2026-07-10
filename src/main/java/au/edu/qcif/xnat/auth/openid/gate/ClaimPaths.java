package au.edu.qcif.xnat.auth.openid.gate;

import com.nimbusds.jwt.JWTClaimsSet;
import org.apache.commons.lang3.StringUtils;

import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;

/**
 * Helpers for reading nested values out of a {@link JWTClaimsSet}.
 *
 * <p>These helpers walk the structured {@link JWTClaimsSet#getClaims()} map so gates can read
 * deeply nested values like {@code resource_access.xnat.roles}.</p>
 */
final class ClaimPaths {

    private ClaimPaths() {
    }

    /**
     * Walks the nested claims map segment by segment.
     *
     * @return the value at the given path, or {@code null} if any segment is missing or an
     * intermediate segment is not a map.
     */
    static Object navigate(final JWTClaimsSet claims, final String[] path) {
        Object current = claims.getClaims();
        for (final String segment : path) {
            if (!(current instanceof Map)) {
                return null;
            }
            current = ((Map<?, ?>) current).get(segment);
        }
        return current;
    }

    /**
     * Navigates to {@code path} and coerces the leaf into a set of role names, accepting a
     * {@code Collection}, an array, or a space-delimited {@code String}.
     *
     * @return the roles found, or an empty set if the path is absent or the leaf is null.
     */
    static Set<String> extractRoles(final JWTClaimsSet claims, final String[] path) {
        final Object leaf = navigate(claims, path);
        if (leaf == null) {
            return Collections.emptySet();
        }
        final Set<String> roles = new LinkedHashSet<>();
        if (leaf instanceof Collection) {
            for (final Object role : (Collection<?>) leaf) {
                if (role != null) {
                    roles.add(role.toString());
                }
            }
        } else if (leaf instanceof Object[]) {
            for (final Object role : (Object[]) leaf) {
                if (role != null) {
                    roles.add(role.toString());
                }
            }
        } else if (leaf instanceof String) {
            roles.addAll(Arrays.asList(StringUtils.split((String) leaf)));
        }
        return roles;
    }
}

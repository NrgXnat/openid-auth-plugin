package au.edu.qcif.xnat.auth.openid.gate;

import au.edu.qcif.xnat.auth.openid.OpenIdAuthPlugin;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.nrg.xdat.security.helpers.Roles;
import org.nrg.xdat.security.helpers.Users;
import org.nrg.xft.security.UserI;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Keeps an OpenID user's XNAT roles in step with roles their token carries, on every sign-in.
 *
 * <p>Configured per provider, with the usual path-scoped override ({@link GateConfig}):
 * {@code openid.{p}.roleSync.enabled} and {@code openid.{p}.roleSync.mappings}, a comma-separated
 * list of {@code <claim path>:<token role>=<XNAT role>} entries, for example
 * {@code resource_access.xnat.roles:xnat-admin=Administrator}.</p>
 *
 * <p>Only XNAT roles named in a mapping are managed. A managed role is granted when a mapping for
 * it matches and removed when the token carries one of its claim paths but no mapping matches. A
 * token that carries none of a role's claim paths leaves that role as it is, so a token minted for
 * another client, without that client's roles, does not undo what the other client granted.</p>
 */
@Slf4j
public class RoleSync {

    /** How roles are read and changed; replaced in tests. */
    public interface RoleStore {
        Collection<String> roles(UserI user);

        void add(UserI user, String role) throws Exception;

        void remove(UserI user, String role) throws Exception;

        UserI reload(UserI user);
    }

    static final class Mapping {
        final String[] path;
        final String tokenRole;
        final String xnatRole;

        Mapping(final String[] path, final String tokenRole, final String xnatRole) {
            this.path = path;
            this.tokenRole = tokenRole;
            this.xnatRole = xnatRole;
        }
    }

    private final OpenIdAuthPlugin plugin;
    private final RoleStore store;

    public RoleSync(final OpenIdAuthPlugin plugin) {
        this(plugin, new XnatRoleStore());
    }

    RoleSync(final OpenIdAuthPlugin plugin, final RoleStore store) {
        this.plugin = plugin;
        this.store = store;
    }

    /**
     * Applies the provider's role mappings to {@code user} and returns the user to authenticate: a
     * freshly loaded copy when a role changed, so its authorities reflect the change, otherwise the
     * same instance. A failure to change a role is logged and grants nothing.
     */
    public UserI apply(final String providerId, final AuthPath authPath, final TokenContext token, final UserI user) {
        final GateConfig config = new GateConfig(plugin, providerId, authPath);
        if (user == null || !config.enabled("roleSync")) {
            return user;
        }
        final Map<String, List<Mapping>> byRole = new LinkedHashMap<>();
        for (final Mapping mapping : parse(config.value("roleSync.mappings"))) {
            byRole.computeIfAbsent(mapping.xnatRole, role -> new ArrayList<>()).add(mapping);
        }
        if (byRole.isEmpty()) {
            return user;
        }

        final Set<String> current = new LinkedHashSet<>(store.roles(user));
        boolean changed = false;
        for (final Map.Entry<String, List<Mapping>> entry : byRole.entrySet()) {
            final Boolean wanted = wanted(token, entry.getValue());
            if (wanted == null) {
                continue;
            }
            final String role = entry.getKey();
            final boolean has = current.contains(role);
            try {
                if (wanted && !has) {
                    store.add(user, role);
                    log.info("Role sync for provider '{}' gave user '{}' the XNAT role '{}'", providerId, user.getUsername(), role);
                    changed = true;
                } else if (!wanted && has) {
                    store.remove(user, role);
                    log.info("Role sync for provider '{}' removed the XNAT role '{}' from user '{}'", providerId, role, user.getUsername());
                    changed = true;
                }
            } catch (final Exception e) {
                log.warn("Role sync for provider '{}' could not {} the XNAT role '{}' for user '{}': {}",
                        providerId, wanted ? "add" : "remove", role, user.getUsername(), e.getMessage());
            }
        }
        if (!changed) {
            return user;
        }
        final UserI reloaded = store.reload(user);
        return reloaded != null ? reloaded : user;
    }

    /** True or false when the token carries at least one of the mappings' claim paths, else null. */
    private static Boolean wanted(final TokenContext token, final List<Mapping> mappings) {
        boolean seen = false;
        for (final Mapping mapping : mappings) {
            if (ClaimPaths.navigate(token.claims(), mapping.path) == null) {
                continue;
            }
            seen = true;
            if (ClaimPaths.extractRoles(token.claims(), mapping.path).contains(mapping.tokenRole)) {
                return Boolean.TRUE;
            }
        }
        return seen ? Boolean.FALSE : null;
    }

    static List<Mapping> parse(final String value) {
        if (StringUtils.isBlank(value)) {
            return Collections.emptyList();
        }
        final List<Mapping> mappings = new ArrayList<>();
        for (final String raw : value.split(",")) {
            final String entry = raw.trim();
            if (entry.isEmpty()) {
                continue;
            }
            final int colon = entry.indexOf(':');
            final int equals = entry.lastIndexOf('=');
            if (colon <= 0 || equals <= colon + 1 || equals == entry.length() - 1) {
                log.warn("Ignoring role sync mapping '{}': expected <claim path>:<token role>=<XNAT role>", entry);
                continue;
            }
            final String path = entry.substring(0, colon).trim();
            final String tokenRole = entry.substring(colon + 1, equals).trim();
            final String xnatRole = entry.substring(equals + 1).trim();
            if (path.isEmpty() || tokenRole.isEmpty() || xnatRole.isEmpty()) {
                log.warn("Ignoring role sync mapping '{}': expected <claim path>:<token role>=<XNAT role>", entry);
                continue;
            }
            mappings.add(new Mapping(path.split("\\."), tokenRole, xnatRole));
        }
        return mappings;
    }

    static final class XnatRoleStore implements RoleStore {
        @Override
        public Collection<String> roles(final UserI user) {
            return Roles.getRoles(user);
        }

        @Override
        public void add(final UserI user, final String role) throws Exception {
            Roles.addRole(Users.getAdminUser(), user, role);
        }

        @Override
        public void remove(final UserI user, final String role) throws Exception {
            Roles.deleteRole(Users.getAdminUser(), user, role);
        }

        @Override
        public UserI reload(final UserI user) {
            try {
                return Users.getUser(user.getUsername());
            } catch (final Exception e) {
                log.warn("Could not reload user '{}' after a role change: {}", user.getUsername(), e.getMessage());
                return null;
            }
        }
    }
}

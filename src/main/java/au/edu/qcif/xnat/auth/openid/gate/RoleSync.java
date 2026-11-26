package au.edu.qcif.xnat.auth.openid.gate;

import au.edu.qcif.xnat.auth.openid.OpenIdAuthPlugin;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.exception.ExceptionUtils;
import org.nrg.xdat.XDAT;
import org.nrg.xdat.preferences.SiteConfigPreferences;
import org.nrg.xdat.security.helpers.Roles;
import org.nrg.xdat.security.helpers.Users;
import org.nrg.xdat.security.services.RoleRepositoryServiceI.RoleDefinitionI;
import org.nrg.xft.security.UserI;

import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.TreeSet;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

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
 * another client, without that client's roles, does not undo what the other client granted. A role
 * that XNAT doesn't define is never granted, though it is still removed. No role is ever removed from
 * the site's primary administrator account or its received-file user: XNAT does its own work as those
 * accounts and expects both to be administrators.</p>
 *
 * <p>Every role sync message starts {@code Role sync}. {@link #reportSettings} says at startup what role
 * sync will do and what is wrong with its settings; {@link #apply} logs each change at {@code INFO}, each
 * failure at {@code WARN}, and each role it leaves as it is at {@code DEBUG}.</p>
 */
@Slf4j
public class RoleSync {

    /** How roles are read and changed; replaced in tests. */
    public interface RoleStore {
        Collection<String> roles(UserI user);

        /** Adds {@code role} to {@code user}; false when XNAT made no change. */
        boolean add(UserI user, String role) throws Exception;

        /** Removes {@code role} from {@code user}; false when XNAT made no change. */
        boolean remove(UserI user, String role) throws Exception;

        /** The user as XNAT now has it, after a role change; throws when XNAT can't load it. */
        UserI reload(UserI user) throws Exception;

        /**
         * The XNAT setting that makes {@code user} an account XNAT does its own work as,
         * {@code primaryAdminUsername} or {@code receivedFileUser}, or null for any other account. Role sync
         * never takes a role from such an account.
         */
        String protectedBy(UserI user);

        /** The names of the roles XNAT defines; empty when XNAT can't say. */
        Set<String> definedRoles();
    }

    /** The role sync settings: {@code openid.<provider>.[idToken.|bearer.]roleSync.(enabled|mappings)}. */
    private static final Pattern SETTING =
            Pattern.compile("openid\\.(.+?)\\.(?:(?:idToken|bearer)\\.)?roleSync\\.(?:enabled|mappings)");
    private static final String SETTING_FORMS = "openid.<provider>.roleSync.enabled or .mappings, "
            + "optionally with idToken. or bearer. before roleSync (names are case-sensitive)";

    /** How every message about one provider and path starts; its two arguments are the provider ID and the path. */
    private static final String LOG_PREFIX = "Role sync for provider '{}' on the {} path ";

    private final OpenIdAuthPlugin plugin;
    private final RoleStore store;
    /** The keys of warnings already written, so one that would repeat at every sign-in is written once. */
    private final Set<String> warned = ConcurrentHashMap.newKeySet();

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
     * same instance. A change that fails is logged and leaves the role as it was. If XNAT can't read the
     * user's current roles, that is logged and the sign-in fails.
     */
    public UserI apply(final String providerId, final AuthPath authPath, final TokenContext token, final UserI user) {
        final GateConfig config = new GateConfig(plugin, providerId, authPath);
        if (user == null || !config.enabled("roleSync")) {
            return user;
        }
        final Map<String, List<RoleSyncMapping>> byRole = new LinkedHashMap<>();
        for (final RoleSyncMapping mapping : RoleSyncMapping.parse(config.value("roleSync.mappings")).mappings()) {
            byRole.computeIfAbsent(mapping.xnatRole, role -> new ArrayList<>()).add(mapping);
        }
        if (byRole.isEmpty()) {
            return user;
        }

        final String path = authPath.prefix();
        final Set<String> current = currentRoles(providerId, path, user);
        boolean changed = false;
        for (final Map.Entry<String, List<RoleSyncMapping>> entry : byRole.entrySet()) {
            final String role = entry.getKey();
            final Boolean wanted = wanted(providerId, path, token, entry.getValue());
            if (wanted == null) {
                log.debug(LOG_PREFIX + "left the XNAT role '{}' of user '{}' as it is: "
                        + "the token doesn't carry its claim path", providerId, path, role, user.getUsername());
            } else if (wanted == current.contains(role)) {
                log.debug(LOG_PREFIX + "made no change to the XNAT role '{}' of user '{}': the user {} it",
                        providerId, path, role, user.getUsername(), wanted ? "already has" : "doesn't have");
            } else if (wanted) {
                changed |= add(providerId, path, user, role);
            } else {
                changed |= remove(providerId, path, user, role);
            }
        }
        if (!changed) {
            return user;
        }
        try {
            final UserI reloaded = store.reload(user);
            return reloaded != null ? reloaded : user;
        } catch (final Exception e) {
            log.warn(LOG_PREFIX + "changed the XNAT roles of user '{}' but could not reload the account: {}",
                    providerId, path, user.getUsername(), cause(e));
            return user;
        }
    }

    /** The user's current XNAT roles; when XNAT can't read them, says so and lets the sign-in fail. */
    private Set<String> currentRoles(final String providerId, final String path, final UserI user) {
        try {
            return new LinkedHashSet<>(store.roles(user));
        } catch (final RuntimeException e) {
            log.warn(LOG_PREFIX + "could not read the XNAT roles of user '{}', so the sign-in fails: {}",
                    providerId, path, user.getUsername(), cause(e));
            throw e;
        }
    }

    /**
     * Gives {@code user} the role, unless XNAT doesn't define it, which {@link #reportSettings} has already
     * warned about; true when XNAT made the change.
     */
    private boolean add(final String providerId, final String path, final UserI user, final String role) {
        try {
            final Set<String> defined = store.definedRoles();
            if (!defined.isEmpty() && !defined.contains(role)) {
                log.debug(LOG_PREFIX + "did not give user '{}' the XNAT role '{}': XNAT does not define it",
                        providerId, path, user.getUsername(), role);
                return false;
            }
            if (store.add(user, role)) {
                log.info(LOG_PREFIX + "gave user '{}' the XNAT role '{}'", providerId, path, user.getUsername(), role);
                return true;
            }
            log.info(LOG_PREFIX + "asked XNAT to add the role '{}' to user '{}', but XNAT reported no change",
                    providerId, path, role, user.getUsername());
        } catch (final Exception e) {
            reportFailedChange(providerId, path, "add", role, user, e);
        }
        return false;
    }

    /** Takes the role from {@code user}, unless it is a protected account; true when XNAT made the change. */
    private boolean remove(final String providerId, final String path, final UserI user, final String role) {
        try {
            final String setting = store.protectedBy(user);
            if (setting != null) {
                warnOnce(String.join("/", providerId, path, "protected", role, user.getUsername()),
                        LOG_PREFIX + "kept the XNAT role '{}' for user '{}': the account is XNAT's {}",
                        providerId, path, role, user.getUsername(), setting);
                return false;
            }
            if (store.remove(user, role)) {
                log.info(LOG_PREFIX + "removed the XNAT role '{}' from user '{}'",
                        providerId, path, role, user.getUsername());
                return true;
            }
            log.info(LOG_PREFIX + "asked XNAT to remove the role '{}' from user '{}', but XNAT reported no change",
                    providerId, path, role, user.getUsername());
        } catch (final Exception e) {
            reportFailedChange(providerId, path, "remove", role, user, e);
        }
        return false;
    }

    /**
     * Says that a change failed, once for this provider, path, change, role, user, and kind of error: a change
     * that fails is tried again at every sign-in, which on the bearer path is every request.
     */
    private void reportFailedChange(final String providerId, final String path, final String change, final String role,
                                    final UserI user, final Exception e) {
        warnOnce(String.join("/", providerId, path, change, role, user.getUsername(), e.getClass().getName()),
                LOG_PREFIX + "could not {} the XNAT role '{}' for user '{}': {}",
                providerId, path, change, role, user.getUsername(), cause(e));
    }

    /** The root cause of {@code e} on one line, as {@code Class: message}. */
    static String cause(final Throwable e) {
        return StringUtils.removeEnd(StringUtils.normalizeSpace(ExceptionUtils.getRootCauseMessage(e)), ":");
    }

    /**
     * True or false when the token carries at least one of the mappings' claim paths, else null. A claim that
     * can't hold roles (an object, a number, true or false) counts as absent, and is reported once.
     */
    private Boolean wanted(final String providerId, final String path, final TokenContext token,
                           final List<RoleSyncMapping> mappings) {
        boolean seen = false;
        for (final RoleSyncMapping mapping : mappings) {
            final String[] steps = mapping.claimPathSteps();
            final Object claim = ClaimPaths.navigate(token.claims(), steps);
            if (claim == null) {
                continue;
            }
            if (!(claim instanceof Collection || claim instanceof Object[] || claim instanceof String)) {
                warnOnce(String.join("/", providerId, path, "claim", mapping.entry),
                        LOG_PREFIX + "ignores the mapping '{}' for this token: its claim '{}' is neither a list nor "
                                + "a string", providerId, path, mapping.entry, mapping.claimPath);
                continue;
            }
            seen = true;
            if (ClaimPaths.extractRoles(token.claims(), steps).contains(mapping.tokenRole)) {
                return Boolean.TRUE;
            }
        }
        return seen ? Boolean.FALSE : null;
    }

    /**
     * Says what role sync will do for each enabled provider, and everything wrong with its settings: on the
     * ID-token path for every provider, and on the bearer path for those in {@code bearerProviders}, the ones
     * the bearer path serves. Logs nothing when no role sync setting is present.
     */
    public void reportSettings(final Set<String> bearerProviders) {
        reportUnknownSettings();
        for (final String providerId : plugin.getEnabledProviders()) {
            reportSettings(providerId, AuthPath.ID_TOKEN);
            if (bearerProviders.contains(providerId)) {
                reportSettings(providerId, AuthPath.BEARER);
            }
        }
    }

    private void reportSettings(final String providerId, final AuthPath authPath) {
        final GateConfig config = new GateConfig(plugin, providerId, authPath);
        final String path = authPath.prefix();
        final String enabled = config.value("roleSync.enabled");
        if (StringUtils.isNotBlank(enabled) && !"true".equalsIgnoreCase(enabled)
                && !"false".equalsIgnoreCase(enabled)) {
            log.warn(LOG_PREFIX + "is off: {} is '{}'; use true or false",
                    providerId, path, config.key("roleSync.enabled"), RoleSyncMapping.escapeHidden(enabled));
            return;
        }
        final RoleSyncMapping.Parsed parsed = RoleSyncMapping.parse(config.value("roleSync.mappings"));
        if (!config.enabled("roleSync")) {
            if (!parsed.mappings().isEmpty() || !parsed.rejected().isEmpty()) {
                log.info(LOG_PREFIX + "is off because {} is not true, so {} is not used",
                        providerId, path, config.key("roleSync.enabled"), config.key("roleSync.mappings"));
            }
            return;
        }
        final String mappingsKey = config.key("roleSync.mappings");
        for (final RoleSyncMapping.Rejected rejection : parsed.rejected()) {
            log.warn(LOG_PREFIX + "ignores the mapping '{}' in {}: it {}; the format is "
                    + "<claim path>:<token role>=<XNAT role>", providerId, path, rejection.entry(), mappingsKey,
                    rejection.reason().text);
        }
        if (parsed.mappings().isEmpty()) {
            if (parsed.rejected().isEmpty()) {
                log.warn(LOG_PREFIX + "is on but roleSync.mappings is not set, so it does nothing", providerId, path);
            } else {
                log.warn(LOG_PREFIX + "is on but every mapping in {} was rejected (above), so it does nothing",
                        providerId, path, mappingsKey);
            }
            return;
        }
        final Set<String> roles = new TreeSet<>();
        parsed.mappings().forEach(mapping -> roles.add(mapping.xnatRole));
        final Set<String> defined = definedRoles(providerId, path);
        final Set<String> removeOnly = new TreeSet<>();
        for (final String role : roles) {
            if (!defined.isEmpty() && !defined.contains(role)) {
                removeOnly.add(role);
                log.warn(LOG_PREFIX + "will never add the XNAT role '{}': XNAT does not define it, so it is only "
                        + "removed. Defined roles: {}", providerId, path, role, new TreeSet<>(defined));
            }
        }
        final int count = parsed.mappings().size();
        log.info(LOG_PREFIX + "is on, with {} for the XNAT roles {}",
                providerId, path, count == 1 ? "1 mapping" : count + " mappings",
                roles.stream().map(role -> removeOnly.contains(role) ? role + " (remove only)" : role)
                     .collect(Collectors.toList()));
    }

    /** The roles XNAT defines; when XNAT can't say, an empty set and a warning that the path went unchecked. */
    private Set<String> definedRoles(final String providerId, final String path) {
        try {
            final Set<String> defined = store.definedRoles();
            if (defined.isEmpty()) {
                log.warn(LOG_PREFIX + "could not check its mapped XNAT roles: XNAT reported no defined roles, so any "
                        + "mapped role is added, misspelt or not", providerId, path);
            }
            return defined;
        } catch (final RuntimeException e) {
            log.warn(LOG_PREFIX + "could not check its mapped XNAT roles: XNAT's role list could not be read: {}",
                    providerId, path, cause(e));
            return Set.of();
        }
    }

    /**
     * Warns about each setting that looks like a role sync setting but isn't one: a name that is misspelt, or
     * one that names a provider that isn't an enabled OpenID provider. A provider's ID may itself hold a dot.
     */
    private void reportUnknownSettings() {
        final List<String> providers = plugin.getEnabledProviders();
        for (final String key : new TreeSet<>(plugin.getProps().stringPropertyNames())) {
            if (!StringUtils.containsIgnoreCase(key, "roleSync")) {
                continue;
            }
            final Matcher matcher = SETTING.matcher(key);
            if (matcher.matches() && providers.contains(matcher.group(1))) {
                continue;
            }
            if (matcher.matches() && providers.stream().noneMatch(id -> key.startsWith("openid." + id + "."))) {
                log.warn("Role sync ignores the setting '{}': '{}' is not an enabled OpenID provider (enabled: {})",
                        RoleSyncMapping.escapeHidden(key), matcher.group(1), String.join(", ", providers));
            } else {
                log.warn("Role sync ignores the setting '{}': role sync settings are {}",
                        RoleSyncMapping.escapeHidden(key), SETTING_FORMS);
            }
        }
    }

    /** Warns the first time this instance sees {@code key}, then logs the same message at DEBUG. */
    private void warnOnce(final String key, final String format, final Object... args) {
        if (warned.add(key)) {
            log.warn(format, args);
        } else {
            log.debug(format, args);
        }
    }

    static final class XnatRoleStore implements RoleStore {
        @Override
        public Collection<String> roles(final UserI user) {
            return Roles.getRoles(user);
        }

        @Override
        public boolean add(final UserI user, final String role) throws Exception {
            return Roles.addRole(Users.getAdminUser(), user, role);
        }

        @Override
        public boolean remove(final UserI user, final String role) throws Exception {
            return Roles.deleteRole(Users.getAdminUser(), user, role);
        }

        @Override
        public String protectedBy(final UserI user) {
            final String username = user.getUsername();
            final UserI admin = Users.getAdminUser();
            if (admin != null && StringUtils.equals(admin.getUsername(), username)) {
                return "primaryAdminUsername";
            }
            final SiteConfigPreferences preferences = XDAT.getSiteConfigPreferences();
            return preferences != null && StringUtils.equals(preferences.getReceivedFileUser(), username)
                    ? "receivedFileUser" : null;
        }

        @Override
        public Set<String> definedRoles() {
            final Collection<RoleDefinitionI> definitions = Roles.getRoles();
            return definitions == null ? Set.of()
                    : definitions.stream().map(RoleDefinitionI::getKey).filter(Objects::nonNull)
                                 .collect(Collectors.toUnmodifiableSet());
        }

        @Override
        public UserI reload(final UserI user) throws Exception {
            return Users.getUser(user.getUsername());
        }
    }
}

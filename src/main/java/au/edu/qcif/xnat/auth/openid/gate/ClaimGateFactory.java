package au.edu.qcif.xnat.auth.openid.gate;

import au.edu.qcif.xnat.auth.openid.OpenIdAuthPlugin;
import org.apache.commons.lang3.StringUtils;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Assembles the enabled {@link ClaimGate}s for a given (provider, {@link AuthPath}) from the
 * plugin's configuration, following the {@code openid.{providerId}.{prop}} convention.
 *
 * <p>Configuration has two layers:</p>
 * <ol>
 *   <li><strong>What to check</strong> — defined once per provider, e.g.
 *       {@code openid.{p}.audCheck.acceptedAudiences}, {@code openid.{p}.roleCheck.rolePath},
 *       {@code openid.{p}.roleCheck.requiredRoles}.</li>
 *   <li><strong>Whether to check, per path</strong> — booleans defaulting to {@code false}, e.g.
 *       {@code openid.{p}.idToken.roleCheck.enabled}, {@code openid.{p}.bearer.audCheck.enabled}.</li>
 * </ol>
 *
 * <p>Any "what to check" field may be overridden per path: a path-scoped value such as
 * {@code openid.{p}.bearer.roleCheck.rolePath} wins over the shared
 * {@code openid.{p}.roleCheck.rolePath}, for when the access token's claim shape diverges from the
 * ID token's. An all-off configuration yields an empty list (a no-op).</p>
 */
public class ClaimGateFactory {

    private final OpenIdAuthPlugin plugin;

    public ClaimGateFactory(final OpenIdAuthPlugin plugin) {
        this.plugin = plugin;
    }

    /**
     * @return the gates enabled for this provider on this path, in a stable order
     * (audience then role); empty if none are enabled.
     */
    public List<ClaimGate> gatesFor(final String providerId, final AuthPath path) {
        final List<ClaimGate> gates = new ArrayList<>();
        if (isEnabled(providerId, path, "audCheck")) {
            gates.add(new AudienceGate(commaSet(resolve(providerId, path, "audCheck.acceptedAudiences"))));
        }
        if (isEnabled(providerId, path, "roleCheck")) {
            final String rolePath = StringUtils.trimToEmpty(resolve(providerId, path, "roleCheck.rolePath"));
            gates.add(new RoleGate(rolePath.split("\\."), commaSet(resolve(providerId, path, "roleCheck.requiredRoles"))));
        }
        return gates;
    }

    /** True if {@code openid.{p}.{path}.{gate}.enabled} is set to {@code true}. */
    private boolean isEnabled(final String providerId, final AuthPath path, final String gate) {
        return Boolean.parseBoolean(plugin.getProperty(providerId, path.prefix() + "." + gate + ".enabled"));
    }

    /** Resolves a "what to check" field, preferring the path-scoped value over the shared one. */
    private String resolve(final String providerId, final AuthPath path, final String field) {
        final String perPath = plugin.getProperty(providerId, path.prefix() + "." + field);
        return StringUtils.isNotBlank(perPath) ? perPath : plugin.getProperty(providerId, field);
    }

    private static Set<String> commaSet(final String value) {
        if (StringUtils.isBlank(value)) {
            return new LinkedHashSet<>();
        }
        return Arrays.stream(value.split("\\s*,\\s*"))
                .filter(StringUtils::isNotBlank)
                .collect(Collectors.toCollection(LinkedHashSet::new));
    }
}

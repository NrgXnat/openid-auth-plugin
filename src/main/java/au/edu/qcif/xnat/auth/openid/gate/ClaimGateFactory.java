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
        final GateConfig config = new GateConfig(plugin, providerId, path);
        final List<ClaimGate> gates = new ArrayList<>();
        if (config.enabled("audCheck")) {
            gates.add(new AudienceGate(commaSet(config.value("audCheck.acceptedAudiences"))));
        }
        if (config.enabled("roleCheck")) {
            final String rolePath = StringUtils.trimToEmpty(config.value("roleCheck.rolePath"));
            gates.add(new RoleGate(rolePath.split("\\."), commaSet(config.value("roleCheck.requiredRoles"))));
        }
        return gates;
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

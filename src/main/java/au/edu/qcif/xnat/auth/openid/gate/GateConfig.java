package au.edu.qcif.xnat.auth.openid.gate;

import au.edu.qcif.xnat.auth.openid.OpenIdAuthPlugin;
import org.apache.commons.lang3.StringUtils;

/**
 * Resolves claim-gate configuration for one {@code (provider, path)} pair, centralizing the two
 * resolution rules so callers never hand-build property names or pick the wrong fallback behaviour.
 *
 * <p>Both accessors follow the {@code openid.{providerId}.{prop}} convention via
 * {@link OpenIdAuthPlugin#getProperty(String, String)}:</p>
 * <ul>
 *   <li>{@link #value(String)} — a "what to check" field (e.g. {@code roleCheck.rolePath}); prefers
 *       the path-scoped key, falling back to the shared per-provider key.</li>
 *   <li>{@link #enabled(String)} — a "whether to check" boolean toggle (e.g. {@code audCheck}),
 *       read per path only and defaulting to {@code false}.</li>
 * </ul>
 */
final class GateConfig {

    private final OpenIdAuthPlugin plugin;
    private final String providerId;
    private final AuthPath path;

    GateConfig(final OpenIdAuthPlugin plugin, final String providerId, final AuthPath path) {
        this.plugin = plugin;
        this.providerId = providerId;
        this.path = path;
    }

    /**
     * Resolves a "what to check" field, preferring the path-scoped value
     * ({@code openid.{p}.{path}.{field}}) over the shared one ({@code openid.{p}.{field}}).
     */
    String value(final String field) {
        final String perPath = plugin.getProperty(providerId, path.prefix() + "." + field);
        return StringUtils.isNotBlank(perPath) ? perPath : plugin.getProperty(providerId, field);
    }

    /**
     * True if {@code openid.{p}.{path}.{gate}.enabled} is set to {@code true}. Read per path only,
     * defaulting to {@code false} when unset.
     */
    boolean enabled(final String gate) {
        return Boolean.parseBoolean(plugin.getProperty(providerId, path.prefix() + "." + gate + ".enabled"));
    }
}

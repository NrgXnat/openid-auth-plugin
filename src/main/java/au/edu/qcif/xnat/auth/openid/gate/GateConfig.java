package au.edu.qcif.xnat.auth.openid.gate;

import au.edu.qcif.xnat.auth.openid.OpenIdAuthPlugin;
import org.apache.commons.lang3.StringUtils;

/**
 * Resolves claim-gate configuration for one {@code (provider, path)} pair, centralizing the two
 * resolution rules so callers never hand-build property names or pick the wrong fallback behaviour.
 *
 * <p>Both accessors follow the {@code openid.{providerId}.{prop}} convention via
 * {@link OpenIdAuthPlugin#getProperty(String, String)}, and both resolve the same way: prefer the
 * path-scoped key, falling back to the shared per-provider key.</p>
 * <ul>
 *   <li>{@link #value(String)} — a "what to check" field (e.g. {@code roleCheck.rolePath}).</li>
 *   <li>{@link #enabled(String)} — a "whether to check" boolean toggle (e.g. {@code audCheck}),
 *       defaulting to {@code false}.</li>
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
        return resolve(field);
    }

    /**
     * True if the {@code {gate}.enabled} toggle resolves to {@code true}, preferring the path-scoped
     * key ({@code openid.{p}.{path}.{gate}.enabled}) over the shared one
     * ({@code openid.{p}.{gate}.enabled}). Defaults to {@code false} when neither is set, so a
     * path-scoped {@code false} also overrides a shared {@code true}.
     */
    boolean enabled(final String gate) {
        return Boolean.parseBoolean(resolve(gate + ".enabled"));
    }

    /** Path-scoped value ({@code openid.{p}.{path}.{field}}), falling back to the shared
     * per-provider value ({@code openid.{p}.{field}}). */
    private String resolve(final String field) {
        final String perPath = plugin.getProperty(providerId, path.prefix() + "." + field);
        return StringUtils.isNotBlank(perPath) ? perPath : plugin.getProperty(providerId, field);
    }
}

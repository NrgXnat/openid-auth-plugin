package au.edu.qcif.xnat.auth.openid.gate;

import au.edu.qcif.xnat.auth.openid.OpenIdAuthPlugin;
import org.apache.commons.lang3.StringUtils;

/**
 * Resolves claim-gate configuration for one {@code (provider, path)} pair, centralizing the two
 * resolution rules so callers never hand-build property names or pick the wrong fallback behaviour.
 *
 * <p>Both accessors follow the {@code openid.{providerId}.{prop}} convention via
 * {@link OpenIdAuthPlugin#getProperty(String, String)}, and both resolve the same way: prefer the
 * path-scoped key, falling back to the shared per-provider key. The same path-scoped resolution is
 * reused for non-gate per-path properties such as {@code forceUserCreate}.</p>
 * <ul>
 *   <li>{@link #value(String)} — a "what to check" field (e.g. {@code roleCheck.rolePath}).</li>
 *   <li>{@link #enabled(String)} — a "whether to check" boolean toggle (e.g. {@code audCheck}),
 *       defaulting to {@code false} except where {@link #defaultEnabled(String)} says otherwise.</li>
 * </ul>
 */
public final class GateConfig {

    private final OpenIdAuthPlugin plugin;
    private final String providerId;
    private final AuthPath path;

    public GateConfig(final OpenIdAuthPlugin plugin, final String providerId, final AuthPath path) {
        this.plugin = plugin;
        this.providerId = providerId;
        this.path = path;
    }

    /**
     * Resolves a "what to check" field, preferring the path-scoped value
     * ({@code openid.{p}.{path}.{field}}) over the shared one ({@code openid.{p}.{field}}). Also used
     * for per-path non-gate properties (e.g. {@code forceUserCreate}).
     */
    public String value(final String field) {
        return resolve(field);
    }

    /**
     * True if the {@code {gate}.enabled} toggle resolves to {@code true}, preferring the path-scoped
     * key ({@code openid.{p}.{path}.{gate}.enabled}) over the shared one
     * ({@code openid.{p}.{gate}.enabled}). When neither is set the gate falls back to
     * {@link #defaultEnabled(String)}; an explicitly configured value (including a path-scoped
     * {@code false} overriding a shared {@code true}) always wins over that default.
     */
    public boolean enabled(final String gate) {
        final String resolved = resolve(gate + ".enabled");
        return StringUtils.isNotBlank(resolved) ? Boolean.parseBoolean(resolved) : defaultEnabled(gate);
    }

    /**
     * The default for a gate's enable toggle when neither the path-scoped nor the shared key is set.
     * Gates are off by default, with one exception: the audience gate on the bearer path. A bearer
     * token arrives from an untrusted client, so the {@code aud} check is the confinement boundary
     * that stops a token minted for another client from being replayed against XNAT; defaulting it on
     * makes the bearer path fail closed. An administrator can still turn it off explicitly with
     * {@code openid.{p}.bearer.audCheck.enabled=false}.
     */
    private boolean defaultEnabled(final String gate) {
        return path == AuthPath.BEARER && "audCheck".equals(gate);
    }

    /** Path-scoped value ({@code openid.{p}.{path}.{field}}), falling back to the shared
     * per-provider value ({@code openid.{p}.{field}}). */
    private String resolve(final String field) {
        final String perPath = plugin.getProperty(providerId, path.prefix() + "." + field);
        return StringUtils.isNotBlank(perPath) ? perPath : plugin.getProperty(providerId, field);
    }
}

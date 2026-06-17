package au.edu.qcif.xnat.auth.openid;

import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

/**
 * Routes an inbound bearer token to the configured provider whose issuer matches the token's
 * {@code iss} claim. The map is built once, at construction, from the providers that are eligible for
 * the bearer path: {@code openid.{p}.bearer.enabled=true} with both an {@code openid.{p}.issuer} and
 * an {@code openid.{p}.jwksUri} configured.
 *
 * <p>A bearer-enabled provider missing its {@code issuer} or {@code jwksUri} is <strong>excluded</strong>
 * (fail-closed) and logged at error level rather than aborting startup: its tokens simply cannot be
 * routed, so they are rejected as coming from an unknown issuer instead of being honored on a
 * half-configured trust relationship.</p>
 */
@Slf4j
class BearerProviderResolver {

    /** Maps a configured issuer to the providerId that trusts it. */
    private final Map<String, String> providerIdByIssuer;

    BearerProviderResolver(final OpenIdAuthPlugin plugin) {
        final Map<String, String> map = new LinkedHashMap<>();
        for (final String providerId : plugin.getEnabledProviders()) {
            if (!Boolean.parseBoolean(plugin.getProperty(providerId, "bearer.enabled"))) {
                continue;
            }
            final String issuer = StringUtils.trimToNull(plugin.getProperty(providerId, "issuer"));
            final String jwksUri = StringUtils.trimToNull(plugin.getProperty(providerId, "jwksUri"));
            if (issuer == null || jwksUri == null) {
                log.error("Provider '{}' has bearer.enabled=true but is missing {} — the bearer path is "
                                + "disabled for it until configured.", providerId,
                        issuer == null ? "openid." + providerId + ".issuer" : "openid." + providerId + ".jwksUri");
                continue;
            }
            final String previous = map.putIfAbsent(issuer, providerId);
            if (previous != null) {
                log.warn("Providers '{}' and '{}' both claim issuer '{}'; keeping '{}'.",
                        previous, providerId, issuer, previous);
            }
        }
        this.providerIdByIssuer = map;
    }

    /** @return the providerId configured to trust this issuer, or empty if none. */
    Optional<String> resolve(final String issuer) {
        if (StringUtils.isBlank(issuer)) {
            return Optional.empty();
        }
        return Optional.ofNullable(providerIdByIssuer.get(issuer));
    }

    /** @return the providerIds eligible for the bearer path, in configuration order. */
    Set<String> providerIds() {
        return Collections.unmodifiableSet(new java.util.LinkedHashSet<>(providerIdByIssuer.values()));
    }
}

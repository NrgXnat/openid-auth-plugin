package au.edu.qcif.xnat.auth.openid;

import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import static au.edu.qcif.xnat.auth.openid.etc.OpenIdAuthConstant.ISSUER;
import static au.edu.qcif.xnat.auth.openid.etc.OpenIdAuthConstant.JWKS_URI;

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
            final String issuer = StringUtils.trimToNull(plugin.getProperty(providerId, ISSUER));
            final String jwksUri = StringUtils.trimToNull(plugin.getProperty(providerId, JWKS_URI));
            if (issuer == null || jwksUri == null) {
                final String missing;
                if (issuer == null && jwksUri == null) {
                    missing = "openid." + providerId + "." + ISSUER + " and openid." + providerId + "." + JWKS_URI;
                } else if (issuer == null) {
                    missing = "openid." + providerId + "." + ISSUER;
                } else {
                    missing = "openid." + providerId + "." + JWKS_URI;
                }
                log.error("Provider '{}' has bearer.enabled=true but is missing {} — the bearer path is "
                                + "disabled for it until configured.", providerId, missing);
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
        return Collections.unmodifiableSet(new LinkedHashSet<>(providerIdByIssuer.values()));
    }
}

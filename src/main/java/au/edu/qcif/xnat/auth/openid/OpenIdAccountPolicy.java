package au.edu.qcif.xnat.auth.openid;

import lombok.extern.slf4j.Slf4j;
import org.apache.commons.collections.ListUtils;
import org.apache.commons.lang3.StringUtils;
import org.nrg.xdat.preferences.SiteConfigPreferences;
import org.nrg.xft.security.UserI;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.function.Function;
import java.util.stream.Collectors;

/**
 * Path-agnostic account-eligibility policy applied once an OpenID identity has been resolved: the
 * per-provider email-domain whitelist ({@code openid.{p}.shouldFilterEmailDomains} /
 * {@code allowedEmailDomains}) and the site-wide email-verification requirement
 * ({@code SiteConfigPreferences#getEmailVerification()}).
 *
 * <p>Both authentication paths consult this so they enforce the same administrator policy: the
 * interactive {@link OpenIdConnectFilter} and the bearer-token filter. Each path maps a rejection to
 * its own response (the interactive path to an exception/redirect, the bearer path to a 403); this
 * class only renders the decision, never the response.</p>
 */
@Slf4j
public class OpenIdAccountPolicy {

    private static final List<String> ALL_DOMAINS = Collections.singletonList("*");

    private final OpenIdAuthPlugin plugin;
    private final SiteConfigPreferences siteConfigPreferences;
    private final Map<String, List<String>> allowedDomainsByProvider;

    public OpenIdAccountPolicy(final OpenIdAuthPlugin plugin, final SiteConfigPreferences siteConfigPreferences) {
        this.plugin = plugin;
        this.siteConfigPreferences = siteConfigPreferences;
        this.allowedDomainsByProvider = plugin.getEnabledProviders().stream()
                .collect(Collectors.toMap(Function.identity(), this::allowedEmailDomains));
    }

    /** Whether the provider is configured to restrict logins to a whitelist of email domains. */
    public boolean shouldFilterEmailDomains(final String providerId) {
        return Boolean.parseBoolean(StringUtils.defaultIfBlank(plugin.getProperty(providerId, "shouldFilterEmailDomains"), "false"));
    }

    /**
     * @return whether the given email's domain is permitted for the provider. Returns {@code true}
     * when domain filtering is off or the whitelist is the {@code *} wildcard; {@code false} for an
     * unknown provider or an email whose domain is absent from the whitelist. Callers that only want
     * to act when filtering is actually on should gate on {@link #shouldFilterEmailDomains(String)}.
     */
    public boolean isEmailDomainAllowed(final String email, final String providerId) {
        if (!allowedDomainsByProvider.containsKey(providerId)) {
            return false;
        }
        if (!shouldFilterEmailDomains(providerId)) {
            return true;
        }
        final List<String> allowedDomains = allowedDomainsByProvider.get(providerId);
        if (ListUtils.isEqualList(ALL_DOMAINS, allowedDomains)) {
            return true;
        }
        final String[] emailParts = email == null ? new String[0] : email.split("@");
        final String domain = emailParts.length >= 2 ? emailParts[1] : null;
        if (StringUtils.isBlank(domain)) {
            log.warn("Couldn't parse a domain from the email address {}, returning false", email);
            return false;
        }
        if (allowedDomains.contains(StringUtils.lowerCase(domain))) {
            log.debug("Matched email {} with allowed domain for provider {}", email, providerId);
            return true;
        }
        log.debug("Email {} did not match any allowed domains for provider {}: {}", email, providerId, allowedDomains);
        return false;
    }

    /**
     * @return whether the site requires email verification and this account is not yet verified, in
     * which case the identity must not be authenticated until the email is confirmed.
     */
    public boolean isEmailVerificationRequired(final UserI user) {
        return siteConfigPreferences.getEmailVerification() && !user.isVerified();
    }

    private List<String> allowedEmailDomains(final String providerId) {
        return shouldFilterEmailDomains(providerId)
                ? Arrays.stream(plugin.getProperty(providerId, "allowedEmailDomains").split("\\s*,\\s*"))
                .map(StringUtils::lowerCase)
                .collect(Collectors.toList())
                : ALL_DOMAINS;
    }
}

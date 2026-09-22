package au.edu.qcif.xnat.auth.openid;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;
import org.nrg.xdat.preferences.SiteConfigPreferences;
import org.nrg.xft.security.UserI;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link OpenIdAccountPolicy}: the shared, path-agnostic account-eligibility checks
 * (email-domain whitelist and the site-wide email-verification requirement) that both the interactive
 * and bearer-token paths enforce. These were previously exercised through {@code OpenIdConnectFilter}'s
 * private methods; they now live with the policy that owns the logic.
 */
@RunWith(MockitoJUnitRunner.class)
public class OpenIdAccountPolicyTest {

    private static final String PROVIDER = "keycloak";

    @Mock private OpenIdAuthPlugin      plugin;
    @Mock private SiteConfigPreferences siteConfigPreferences;

    private OpenIdAccountPolicy policyWith(final Map<String, String> providerProps) {
        lenient().when(plugin.getEnabledProviders()).thenReturn(Collections.singletonList(PROVIDER));
        providerProps.forEach((key, value) -> lenient().when(plugin.getProperty(PROVIDER, key)).thenReturn(value));
        return new OpenIdAccountPolicy(plugin, siteConfigPreferences);
    }

    private static Map<String, String> filteringOn(final String allowedEmailDomains) {
        final Map<String, String> props = new HashMap<>();
        props.put("shouldFilterEmailDomains", "true");
        props.put("allowedEmailDomains", allowedEmailDomains);
        return props;
    }

    // ---- email-domain whitelisting -------------------------------------------------------------

    @Test
    public void anyDomainAllowedWhenFilteringDisabled() {
        final OpenIdAccountPolicy policy = policyWith(Collections.singletonMap("shouldFilterEmailDomains", "false"));

        assertTrue(policy.isEmailDomainAllowed("anyone@whatever.example", PROVIDER));
    }

    @Test
    public void domainOnWhitelistIsAllowed() {
        final OpenIdAccountPolicy policy = policyWith(filteringOn("example.org, wustl.edu"));

        assertTrue(policy.isEmailDomainAllowed("jane@wustl.edu", PROVIDER));
    }

    @Test
    public void domainNotOnWhitelistIsRejected() {
        final OpenIdAccountPolicy policy = policyWith(filteringOn("example.org, wustl.edu"));

        assertFalse(policy.isEmailDomainAllowed("jane@gmail.com", PROVIDER));
    }

    @Test
    public void whitelistMatchIsCaseInsensitive() {
        final OpenIdAccountPolicy policy = policyWith(filteringOn("wustl.edu"));

        assertTrue(policy.isEmailDomainAllowed("Jane@WUSTL.EDU", PROVIDER));
    }

    @Test
    public void wildcardWhitelistAllowsAnyDomain() {
        final OpenIdAccountPolicy policy = policyWith(filteringOn("*"));

        assertTrue(policy.isEmailDomainAllowed("jane@anything.example", PROVIDER));
    }

    @Test
    public void malformedEmailWithoutDomainIsRejected() {
        final OpenIdAccountPolicy policy = policyWith(filteringOn("wustl.edu"));

        assertFalse("an address with no @ has no parseable domain", policy.isEmailDomainAllowed("not-an-email", PROVIDER));
    }

    @Test
    public void unknownProviderIsRejected() {
        // Only PROVIDER is enabled; a different provider id is absent from the allowed-domains map.
        final OpenIdAccountPolicy policy = policyWith(filteringOn("wustl.edu"));

        assertFalse(policy.isEmailDomainAllowed("jane@wustl.edu", "some-other-provider"));
    }

    @Test
    public void shouldFilterEmailDomainsDefaultsToFalseWhenUnset() {
        final OpenIdAccountPolicy policy = policyWith(Collections.emptyMap());

        assertFalse(policy.shouldFilterEmailDomains(PROVIDER));
    }

    @Test
    public void shouldFilterEmailDomainsReflectsConfiguredValue() {
        final OpenIdAccountPolicy policy = policyWith(filteringOn("wustl.edu"));

        assertTrue(policy.shouldFilterEmailDomains(PROVIDER));
    }

    // ---- email verification --------------------------------------------------------------------

    @Test
    public void verificationNotRequiredWhenSitePreferenceOff() {
        final OpenIdAccountPolicy policy = policyWith(Collections.emptyMap());
        when(siteConfigPreferences.getEmailVerification()).thenReturn(false);
        final UserI unverified = mock(UserI.class);
        lenient().when(unverified.isVerified()).thenReturn(false);

        assertFalse(policy.isEmailVerificationRequired(unverified));
    }

    @Test
    public void verificationRequiredWhenSitePreferenceOnAndUserUnverified() {
        final OpenIdAccountPolicy policy = policyWith(Collections.emptyMap());
        when(siteConfigPreferences.getEmailVerification()).thenReturn(true);
        final UserI unverified = mock(UserI.class);
        when(unverified.isVerified()).thenReturn(false);

        assertTrue(policy.isEmailVerificationRequired(unverified));
    }

    @Test
    public void verificationNotRequiredWhenUserAlreadyVerified() {
        final OpenIdAccountPolicy policy = policyWith(Collections.emptyMap());
        when(siteConfigPreferences.getEmailVerification()).thenReturn(true);
        final UserI verified = mock(UserI.class);
        when(verified.isVerified()).thenReturn(true);

        assertFalse(policy.isEmailVerificationRequired(verified));
    }
}

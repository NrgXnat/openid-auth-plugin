package au.edu.qcif.xnat.auth.openid;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;

import java.util.HashMap;
import java.util.Map;

import static au.edu.qcif.xnat.auth.openid.etc.OpenIdAuthConstant.USERNAME_PATTERN;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.when;

/**
 * Tests that {@code usernamePattern} can name a claim whose key is a URI.
 *
 * <p>Some providers will not emit a custom claim under a bare name. Auth0 requires custom claims to be
 * namespaced — {@code https://example.org/upn} rather than {@code upn} — and drops anything else that is
 * not a registered OIDC claim. The claim itself was always readable; what could not be expressed was the
 * <em>reference</em> to it, because the placeholder syntax accepted only letters, digits and underscore
 * between the brackets. A pattern of {@code [https://example.org/upn]} therefore matched nothing, was
 * left in place as a literal, and produced a username containing the claim name rather than its value.</p>
 *
 * <p>The closing bracket stays excluded from the accepted characters, so a pattern is still unambiguous
 * about where each placeholder ends and multi-placeholder patterns are unaffected.</p>
 */
@RunWith(MockitoJUnitRunner.class)
public class OpenIdConnectUserDetailsNamespacedClaimTest {

    private static final String PROVIDER = "partner";

    @Mock private OpenIdAuthPlugin plugin;

    /** Resolves {@code pattern} against {@code claims} exactly as an inbound token would be. */
    private String usernameFor(final String pattern, final Map<String, Object> claims) {
        when(plugin.getProperty(PROVIDER, USERNAME_PATTERN)).thenReturn(pattern);
        return new OpenIdConnectUserDetails(PROVIDER, claims, null, plugin).getUsername();
    }

    private static Map<String, Object> claims(final String key, final String value) {
        final Map<String, Object> claims = new HashMap<>();
        claims.put(key, value);
        return claims;
    }

    @Test
    public void resolvesAClaimNamedWithAUri() {
        assertEquals("alice@example.org",
                     usernameFor("[https://example.org/upn]",
                                 claims("https://example.org/upn", "alice@example.org")));
    }

    @Test
    public void resolvesAClaimNamedWithAUriThatCarriesAPort() {
        // Colons appear in the scheme and can appear again in an authority, so both have to survive.
        assertEquals("alice@example.org",
                     usernameFor("[https://id.example.org:8443/claims/upn]",
                                 claims("https://id.example.org:8443/claims/upn", "alice@example.org")));
    }

    @Test
    public void resolvesAClaimNamedWithHyphensAndDots() {
        assertEquals("alice@example.org",
                     usernameFor("[urn:partner-corp.example:upn]",
                                 claims("urn:partner-corp.example:upn", "alice@example.org")));
    }

    @Test
    public void stillResolvesABareClaimName() {
        assertEquals("alice@example.org", usernameFor("[upn]", claims("upn", "alice@example.org")));
    }

    @Test
    public void stillResolvesTwoPlaceholdersInOnePattern() {
        // The closing bracket remains excluded, so each placeholder still ends where it did before and a
        // composite pattern does not collapse into a single greedy match.
        final Map<String, Object> claims = claims("sub", "abc123");
        assertEquals(PROVIDER + "_abc123", usernameFor("[providerId]_[sub]", claims));
    }

    @Test
    public void mixesABareAndANamespacedPlaceholder() {
        final Map<String, Object> claims = claims("https://example.org/upn", "alice");
        assertEquals("partner-alice", usernameFor("[providerId]-[https://example.org/upn]", claims));
    }

    /**
     * The startup validation for {@code linkExisting} asks whether a pattern names exactly one claim, and
     * it has to answer that over the same syntax {@code usernamePattern} accepts. It once carried its own
     * copy of the placeholder regex, which kept the pre-URI character class: every one of the URI-named
     * patterns above was reported as "not a single claim, so no link attempt can ever match" — a warning
     * that is false, and false about precisely the configuration a namespaced provider is forced into.
     */
    @Test
    public void namesTheSoleClaimOfAUriNamedPattern() {
        assertEquals("https://example.org/upn",
                     OpenIdConnectUserDetails.soleClaimName("[https://example.org/upn]"));
        assertEquals("urn:partner-corp.example:upn",
                     OpenIdConnectUserDetails.soleClaimName("[urn:partner-corp.example:upn]"));
    }

    @Test
    public void namesTheSoleClaimOfABarePattern() {
        assertEquals("upn", OpenIdConnectUserDetails.soleClaimName("[upn]"));
        assertEquals("sub", OpenIdConnectUserDetails.soleClaimName("[sub]"));
    }

    @Test
    public void namesNoSoleClaimForAPatternThatIsNotOneWholePlaceholder() {
        // The shipped default, a prefixed placeholder, and a bare word: none names one claim and nothing
        // else, which is what makes each of them unable to match a second provider's value.
        assertNull(OpenIdConnectUserDetails.soleClaimName("[providerId]_[sub]"));
        assertNull(OpenIdConnectUserDetails.soleClaimName("x[upn]"));
        assertNull(OpenIdConnectUserDetails.soleClaimName("[upn]-"));
        assertNull(OpenIdConnectUserDetails.soleClaimName("upn"));
        assertNull(OpenIdConnectUserDetails.soleClaimName(null));
    }
}

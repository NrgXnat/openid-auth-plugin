package au.edu.qcif.xnat.auth.openid;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

import static au.edu.qcif.xnat.auth.openid.etc.OpenIdAuthConstant.ISSUER;
import static au.edu.qcif.xnat.auth.openid.etc.OpenIdAuthConstant.JWKS_URI;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.mockito.Mockito.lenient;

/**
 * Unit tests for {@link BearerProviderResolver}: routing an inbound token to the provider whose
 * configured issuer matches the token's {@code iss}. Only providers with {@code bearer.enabled=true}
 * and both an {@code issuer} and a {@code jwksUri} configured are eligible — a bearer-enabled
 * provider missing either is excluded (fail-closed), so its tokens cannot be routed and validated.
 */
@RunWith(MockitoJUnitRunner.class)
public class BearerProviderResolverTest {

    @Mock private OpenIdAuthPlugin plugin;

    /** Stubs one provider's bearer-relevant properties. */
    private void provider(final String id, final String bearerEnabled, final String issuer, final String jwksUri) {
        final Map<String, String> props = new HashMap<>();
        props.put("bearer.enabled", bearerEnabled);
        props.put(ISSUER, issuer);
        props.put(JWKS_URI, jwksUri);
        props.forEach((k, v) -> lenient().when(plugin.getProperty(id, k)).thenReturn(v));
    }

    private BearerProviderResolver resolverFor(final String... providerIds) {
        lenient().when(plugin.getEnabledProviders()).thenReturn(Arrays.asList(providerIds));
        return new BearerProviderResolver(plugin);
    }

    @Test
    public void resolvesMatchingIssuerToProvider() {
        provider("keycloak", "true", "https://idp.example/realms/xnat", "https://idp.example/jwks");
        final BearerProviderResolver resolver = resolverFor("keycloak");

        assertEquals("keycloak", resolver.resolve("https://idp.example/realms/xnat").orElse(null));
    }

    @Test
    public void unknownIssuerResolvesToNothing() {
        provider("keycloak", "true", "https://idp.example/realms/xnat", "https://idp.example/jwks");
        final BearerProviderResolver resolver = resolverFor("keycloak");

        assertFalse(resolver.resolve("https://other.example").isPresent());
    }

    @Test
    public void nullIssuerResolvesToNothing() {
        provider("keycloak", "true", "https://idp.example/realms/xnat", "https://idp.example/jwks");
        final BearerProviderResolver resolver = resolverFor("keycloak");

        assertFalse(resolver.resolve(null).isPresent());
    }

    @Test
    public void providerNotBearerEnabledIsExcludedEvenIfIssuerMatches() {
        provider("keycloak", "false", "https://idp.example/realms/xnat", "https://idp.example/jwks");
        final BearerProviderResolver resolver = resolverFor("keycloak");

        assertFalse(resolver.resolve("https://idp.example/realms/xnat").isPresent());
    }

    @Test
    public void bearerEnabledProviderMissingJwksUriIsExcluded() {
        provider("broken", "true", "https://idp.example/realms/xnat", "  ");
        final BearerProviderResolver resolver = resolverFor("broken");

        assertFalse(resolver.resolve("https://idp.example/realms/xnat").isPresent());
    }

    @Test
    public void bearerEnabledProviderMissingIssuerIsExcluded() {
        provider("broken", "true", "", "https://idp.example/jwks");
        final BearerProviderResolver resolver = resolverFor("broken");

        assertFalse(resolver.resolve("").isPresent());
    }

    @Test
    public void routesAmongMultipleProviders() {
        provider("kc", "true", "https://kc.example", "https://kc.example/jwks");
        provider("auth0", "true", "https://auth0.example", "https://auth0.example/jwks");
        provider("disabled", "false", "https://disabled.example", "https://disabled.example/jwks");
        final BearerProviderResolver resolver = resolverFor("kc", "auth0", "disabled");

        assertEquals("kc", resolver.resolve("https://kc.example").orElse(null));
        assertEquals("auth0", resolver.resolve("https://auth0.example").orElse(null));
        assertFalse(resolver.resolve("https://disabled.example").isPresent());
    }
}

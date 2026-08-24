package au.edu.qcif.xnat.auth.openid;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;
import org.nrg.xdat.entities.XdatUserAuth;
import au.edu.qcif.xnat.auth.openid.gate.AuthPath;
import org.nrg.xdat.services.XdatUserAuthService;

import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertSame;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link OpenIdUserResolver#findLinkSource}: locating the existing provider's mapping
 * whose XNAT account a second provider's identity would be attached to. The lookup must be exact on
 * {@code (matchValue, OPENID, sourceProvider)} — a near miss has to stay a miss, because a loose match
 * here is what would attach one person's provider identity to another person's XNAT account.
 *
 * <p>{@link OpenIdUserResolver#linkExisting} itself is left to integration testing beyond the guards
 * exercised here: past the source lookup it calls XNAT's static {@code Users} and {@code Roles} helpers,
 * so the account-load and site-administrator guards need a live context.</p>
 */
@RunWith(MockitoJUnitRunner.class)
public class OpenIdUserResolverLinkTest {

    private static final String PROVIDER        = "partner";  // the newly added provider
    private static final String SOURCE_PROVIDER = "keycloak"; // the one whose accounts already exist
    private static final String USERNAME        = "alice@example.org";  // both providers key on the same claim

    @Mock private OpenIdAuthPlugin     plugin;
    @Mock private XdatUserAuthService  userAuthService;

    private OpenIdUserResolver resolver() {
        return new OpenIdUserResolver(plugin, userAuthService);
    }

    @Test
    public void findsTheSourceMappingForAMatchingUsername() {
        final XdatUserAuth source = mock(XdatUserAuth.class);
        when(userAuthService.getUserByNameAndAuth(USERNAME, XdatUserAuthService.OPENID, SOURCE_PROVIDER)).thenReturn(source);

        assertSame(source, resolver().findLinkSource(USERNAME, SOURCE_PROVIDER));
    }

    @Test
    public void returnsNullWhenNoMappingMatches() {
        when(userAuthService.getUserByNameAndAuth(USERNAME, XdatUserAuthService.OPENID, SOURCE_PROVIDER)).thenReturn(null);

        assertNull(resolver().findLinkSource(USERNAME, SOURCE_PROVIDER));
    }

    @Test
    public void doesNotQueryOnABlankUsername() {
        assertNull(resolver().findLinkSource("  ", SOURCE_PROVIDER));
        assertNull(resolver().findLinkSource(null, SOURCE_PROVIDER));

        verify(userAuthService, never()).getUserByNameAndAuth(org.mockito.ArgumentMatchers.anyString(),
                org.mockito.ArgumentMatchers.anyString(), org.mockito.ArgumentMatchers.anyString());
    }

    @Test
    public void doesNotQueryOnABlankSourceProvider() {
        assertNull(resolver().findLinkSource(USERNAME, null));
        assertNull(resolver().findLinkSource(USERNAME, ""));

        verify(userAuthService, never()).getUserByNameAndAuth(org.mockito.ArgumentMatchers.anyString(),
                org.mockito.ArgumentMatchers.anyString(), org.mockito.ArgumentMatchers.anyString());
    }

    @Test
    public void aMappingUnderADifferentProviderIsNotAMatch() {
        // The same claim value under another provider must not be reachable: provider scoping is the
        // whole reason two identities for one human stay distinct until deliberately linked.
        when(userAuthService.getUserByNameAndAuth(USERNAME, XdatUserAuthService.OPENID, SOURCE_PROVIDER)).thenReturn(null);

        assertNull(resolver().findLinkSource(USERNAME, SOURCE_PROVIDER));
        verify(userAuthService).getUserByNameAndAuth(USERNAME, XdatUserAuthService.OPENID, SOURCE_PROVIDER);
    }

    // ---- linkExistingIfConfigured: shared config handling for both auth paths ---------------------

    @Test
    public void doesNothingWhenLinkingIsNotEnabled() {
        assertNull(resolver().linkExistingIfConfigured(PROVIDER, AuthPath.BEARER, USERNAME));
        assertNull(resolver().linkExistingIfConfigured(PROVIDER, AuthPath.ID_TOKEN, USERNAME));

        verify(userAuthService, never()).getUserByNameAndAuth(org.mockito.ArgumentMatchers.anyString(),
                org.mockito.ArgumentMatchers.anyString(), org.mockito.ArgumentMatchers.anyString());
    }

    @Test
    public void doesNothingWhenEnabledButNoSourceProviderIsSet() {
        // Fail closed on a half-configured provider rather than guessing which provider to match against.
        when(plugin.getProperty(PROVIDER, "bearer.linkExisting.enabled")).thenReturn("true");

        assertNull(resolver().linkExistingIfConfigured(PROVIDER, AuthPath.BEARER, USERNAME));

        verify(userAuthService, never()).getUserByNameAndAuth(org.mockito.ArgumentMatchers.anyString(),
                org.mockito.ArgumentMatchers.anyString(), org.mockito.ArgumentMatchers.anyString());
    }

    @Test
    public void aSharedSettingAppliesToBothPaths() {
        // openid.{p}.linkExisting.* with no path prefix governs the browser and API paths alike.
        when(plugin.getProperty(PROVIDER, "linkExisting.enabled")).thenReturn("true");
        when(plugin.getProperty(PROVIDER, "linkExisting.sourceProvider")).thenReturn(SOURCE_PROVIDER);
        when(userAuthService.getUserByNameAndAuth(USERNAME, XdatUserAuthService.OPENID, SOURCE_PROVIDER)).thenReturn(null);

        assertNull(resolver().linkExistingIfConfigured(PROVIDER, AuthPath.BEARER, USERNAME));
        assertNull(resolver().linkExistingIfConfigured(PROVIDER, AuthPath.ID_TOKEN, USERNAME));

        // Reached the lookup on both paths, which is what proves the shared key was honoured.
        verify(userAuthService, org.mockito.Mockito.times(2))
                .getUserByNameAndAuth(USERNAME, XdatUserAuthService.OPENID, SOURCE_PROVIDER);
    }

    @Test
    public void aPathScopedFalseOverridesASharedTrue() {
        // A site that wants this on the API path but not the browser one.
        when(plugin.getProperty(PROVIDER, "idToken.linkExisting.enabled")).thenReturn("false");

        assertNull(resolver().linkExistingIfConfigured(PROVIDER, AuthPath.ID_TOKEN, USERNAME));

        verify(userAuthService, never()).getUserByNameAndAuth(org.mockito.ArgumentMatchers.anyString(),
                org.mockito.ArgumentMatchers.anyString(), org.mockito.ArgumentMatchers.anyString());
    }
}

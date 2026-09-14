package au.edu.qcif.xnat.auth.openid;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;
import org.nrg.xdat.entities.XdatUserAuth;
import au.edu.qcif.xnat.auth.openid.gate.AuthPath;
import org.mockito.MockedStatic;
import org.nrg.xdat.XDAT;
import org.nrg.xdat.security.helpers.Users;
import org.nrg.xdat.services.XdatUserAuthService;
import org.nrg.xdat.turbine.utils.AdminUtils;
import org.nrg.xft.security.UserI;
import org.springframework.security.core.AuthenticationException;

import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.mockito.Mockito.withSettings;

/**
 * Unit tests for {@link OpenIdUserResolver#findLinkSource}: locating the existing provider's mapping
 * whose XNAT account a second provider's identity would be attached to. The lookup must be exact on
 * {@code (matchValue, OPENID, sourceProvider)} — a near miss has to stay a miss, because a loose match
 * here is what would attach one person's provider identity to another person's XNAT account.
 *
 * <p>{@link OpenIdUserResolver#linkExisting} is covered here for the paths that do not depend on a live
 * XNAT context, including what happens when a concurrent request creates the same mapping first. The
 * notification it sends on success is left to integration testing.</p>
 */
@RunWith(MockitoJUnitRunner.class)
public class OpenIdUserResolverLinkTest {

    private static final String PROVIDER        = "partner";  // the newly added provider
    private static final String SOURCE_PROVIDER = "keycloak"; // the one whose accounts already exist
    private static final String USERNAME        = "alice@example.org";  // both providers key on the same claim
    private static final String XNAT_LOGIN      = "alice";    // the account both mappings resolve to

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

    // ---- a concurrent request may create the mapping first -----------------------------------------

    /**
     * Linking runs on a lookup miss, and a viewer opening a study issues several requests at once, so the
     * first few can all miss and all try to create the mapping. Only one wins; the rest must not turn a
     * successful link into a failed request.
     */
    @Test
    public void usesTheMappingWhenAConcurrentRequestCreatedItFirst() {
        final XdatUserAuth source = mock(XdatUserAuth.class);
        when(source.getXdatUsername()).thenReturn(XNAT_LOGIN);
        when(userAuthService.getUserByNameAndAuth(USERNAME, XdatUserAuthService.OPENID, SOURCE_PROVIDER))
                .thenReturn(source);

        // The create loses the race...
        doThrow(new RuntimeException("duplicate key"))
                .when(userAuthService).create(org.mockito.ArgumentMatchers.any(XdatUserAuth.class));
        // ...and the winner's mapping is there on the re-read, naming the same account.
        final XdatUserAuth winner = mock(XdatUserAuth.class);
        lenient().when(winner.getXdatUsername()).thenReturn(XNAT_LOGIN);
        when(userAuthService.getUserByNameAndAuth(USERNAME, XdatUserAuthService.OPENID, PROVIDER)).thenReturn(winner);

        try (final MockedStatic<Users> users = mockStatic(Users.class, withSettings().lenient());
             final MockedStatic<AdminUtils> admin = mockStatic(AdminUtils.class, withSettings().lenient());
             final MockedStatic<XDAT> xdat = mockStatic(XDAT.class, withSettings().lenient())) {

            final UserI account = mock(UserI.class);
            users.when(() -> Users.getUser(XNAT_LOGIN)).thenReturn(account);

            assertSame(account, resolver().linkExisting(PROVIDER, USERNAME, SOURCE_PROVIDER));
            verify(account).setAuthorization(winner);
        }
    }

    @Test
    public void stillFailsWhenTheCreateFailedForSomeOtherReason() {
        // Nothing on the re-read means the create genuinely failed, and the caller has to hear about it
        // rather than proceed as though the identity were linked.
        final XdatUserAuth source = mock(XdatUserAuth.class);
        when(source.getXdatUsername()).thenReturn(XNAT_LOGIN);
        when(userAuthService.getUserByNameAndAuth(USERNAME, XdatUserAuthService.OPENID, SOURCE_PROVIDER))
                .thenReturn(source);
        doThrow(new RuntimeException("connection reset"))
                .when(userAuthService).create(org.mockito.ArgumentMatchers.any(XdatUserAuth.class));
        when(userAuthService.getUserByNameAndAuth(USERNAME, XdatUserAuthService.OPENID, PROVIDER)).thenReturn(null);

        try (final MockedStatic<Users> users = mockStatic(Users.class, withSettings().lenient())) {
            users.when(() -> Users.getUser(XNAT_LOGIN)).thenReturn(mock(UserI.class));

            try {
                resolver().linkExisting(PROVIDER, USERNAME, SOURCE_PROVIDER);
                fail("expected the create failure to surface");
            } catch (final AuthenticationException expected) {
                assertTrue(expected.getMessage().contains("link"));
            }
        }
    }
}

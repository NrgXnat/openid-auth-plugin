package au.edu.qcif.xnat.auth.openid;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;
import org.nrg.xdat.entities.XdatUserAuth;
import org.nrg.xdat.exceptions.UsernameAuthMappingNotFoundException;
import org.nrg.xdat.services.XdatUserAuthService;
import org.nrg.xft.security.UserI;

import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.fail;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link OpenIdUserResolver#resolveExisting}: looking up the XNAT user behind an
 * OpenID {@code (username, OPENID, providerId)} mapping. A missing mapping surfaces as
 * {@link UsernameAuthMappingNotFoundException} so each path can decide whether to auto-create or
 * deny. The account-creation path is left to integration testing (it calls XNAT's static {@code Users}
 * helpers).
 */
@RunWith(MockitoJUnitRunner.class)
public class OpenIdUserResolverTest {

    private static final String PROVIDER = "keycloak";
    private static final String USERNAME = "keycloak_alice";

    @Mock private OpenIdAuthPlugin plugin;
    @Mock private XdatUserAuthService userAuthService;

    @Test
    public void returnsExistingMappedUser() {
        final UserI user = mock(UserI.class);
        when(userAuthService.getUserDetailsByNameAndAuth(USERNAME, XdatUserAuthService.OPENID, PROVIDER)).thenReturn(user);

        final OpenIdUserResolver resolver = new OpenIdUserResolver(plugin, userAuthService);

        assertSame(user, resolver.resolveExisting(USERNAME, PROVIDER));
    }

    @Test
    public void propagatesMappingNotFound() {
        when(userAuthService.getUserDetailsByNameAndAuth(USERNAME, XdatUserAuthService.OPENID, PROVIDER))
                .thenThrow(new UsernameAuthMappingNotFoundException(USERNAME, XdatUserAuthService.OPENID, PROVIDER, null, null, null));

        final OpenIdUserResolver resolver = new OpenIdUserResolver(plugin, userAuthService);

        try {
            resolver.resolveExisting(USERNAME, PROVIDER);
            fail("expected UsernameAuthMappingNotFoundException");
        } catch (UsernameAuthMappingNotFoundException expected) {
            // pass — the caller decides whether to auto-create or deny
        }
    }

    /** XNAT reports a mapped account it failed to load (a database timeout, say) as a missing mapping. */
    @Test
    public void aMappedAccountThatFailsToLoadIsUnavailableRatherThanUnmapped() {
        when(userAuthService.getUserDetailsByNameAndAuth(USERNAME, XdatUserAuthService.OPENID, PROVIDER))
                .thenThrow(new UsernameAuthMappingNotFoundException(USERNAME, XdatUserAuthService.OPENID, PROVIDER, null, null, null));
        when(userAuthService.getUserByNameAndAuth(USERNAME, XdatUserAuthService.OPENID, PROVIDER))
                .thenReturn(new XdatUserAuth(USERNAME, XdatUserAuthService.OPENID, PROVIDER));

        final OpenIdUserResolver resolver = new OpenIdUserResolver(plugin, userAuthService);

        assertThrows(AccountUnavailableException.class, () -> resolver.resolveExisting(USERNAME, PROVIDER));
    }

    @Test
    public void aMappingThatCannotBeLookedUpIsUnavailableRatherThanUnmapped() {
        final RuntimeException databaseDown = new IllegalStateException("Unable to acquire JDBC Connection");
        when(userAuthService.getUserDetailsByNameAndAuth(USERNAME, XdatUserAuthService.OPENID, PROVIDER))
                .thenThrow(new UsernameAuthMappingNotFoundException(USERNAME, XdatUserAuthService.OPENID, PROVIDER, null, null, null));
        when(userAuthService.getUserByNameAndAuth(USERNAME, XdatUserAuthService.OPENID, PROVIDER)).thenThrow(databaseDown);

        final OpenIdUserResolver resolver = new OpenIdUserResolver(plugin, userAuthService);

        final AccountUnavailableException thrown =
                assertThrows(AccountUnavailableException.class, () -> resolver.resolveExisting(USERNAME, PROVIDER));
        assertSame(databaseDown, thrown.getCause());
    }
}

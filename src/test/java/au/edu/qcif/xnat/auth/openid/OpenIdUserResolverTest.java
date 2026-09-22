package au.edu.qcif.xnat.auth.openid;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;
import org.nrg.xdat.exceptions.UsernameAuthMappingNotFoundException;
import org.nrg.xdat.services.XdatUserAuthService;
import org.nrg.xft.security.UserI;

import static org.junit.Assert.assertSame;
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
}

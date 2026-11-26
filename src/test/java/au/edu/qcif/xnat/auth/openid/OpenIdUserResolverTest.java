package au.edu.qcif.xnat.auth.openid;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.junit.MockitoJUnitRunner;
import org.nrg.xdat.entities.XdatUserAuth;
import org.nrg.xdat.exceptions.UsernameAuthMappingNotFoundException;
import org.nrg.xdat.security.helpers.Users;
import org.nrg.xdat.security.user.exceptions.UserInitException;
import org.nrg.xdat.security.user.exceptions.UserNotFoundException;
import org.nrg.xdat.services.XdatUserAuthService;
import org.nrg.xft.security.UserI;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.mockito.Mockito.withSettings;

/**
 * Unit tests for {@link OpenIdUserResolver#resolveExisting}: looking up the XNAT user behind an
 * OpenID {@code (username, OPENID, providerId)} mapping. A missing mapping surfaces as
 * {@link UsernameAuthMappingNotFoundException} so each path can decide whether to auto-create or
 * deny; a mapping or account that could not be read surfaces as {@link AccountUnavailableException}.
 */
@RunWith(MockitoJUnitRunner.class)
public class OpenIdUserResolverTest {

    private static final String PROVIDER = "keycloak";
    private static final String USERNAME = "keycloak_alice";
    private static final String XNAT_LOGIN = "alice";

    @Mock private OpenIdAuthPlugin plugin;
    @Mock private XdatUserAuthService userAuthService;

    private MockedStatic<Users> users;
    private OpenIdUserResolver resolver;

    @Before
    public void setUp() {
        users = mockStatic(Users.class, withSettings().lenient());
        resolver = new OpenIdUserResolver(plugin, userAuthService);
    }

    @After
    public void closeStatics() {
        users.close();
    }

    private void mapped() {
        final XdatUserAuth mapping = new XdatUserAuth(USERNAME, XdatUserAuthService.OPENID, PROVIDER);
        mapping.setXdatUsername(XNAT_LOGIN);
        when(userAuthService.getUserByNameAndAuth(USERNAME, XdatUserAuthService.OPENID, PROVIDER)).thenReturn(mapping);
    }

    /** XNAT's getUserDetailsByNameAndAuth builds the user inside its transaction, holding a connection while XFT takes another. */
    @Test
    public void loadsTheMappedUserWithoutXnatsTransactionalLookup() {
        mapped();
        final UserI user = mock(UserI.class);
        users.when(() -> Users.getUser(XNAT_LOGIN)).thenReturn(user);

        assertSame(user, resolver.resolveExisting(USERNAME, PROVIDER));

        final ArgumentCaptor<XdatUserAuth> authorization = ArgumentCaptor.forClass(XdatUserAuth.class);
        verify(user).setAuthorization(authorization.capture());
        assertEquals(USERNAME, authorization.getValue().getAuthUser());
        assertEquals(PROVIDER, authorization.getValue().getAuthMethodId());
        verify(userAuthService, never()).getUserDetailsByNameAndAuth(anyString(), anyString(), anyString());
    }

    @Test
    public void aMissingMappingIsUnmapped() {
        assertThrows(UsernameAuthMappingNotFoundException.class, () -> resolver.resolveExisting(USERNAME, PROVIDER));
        users.verify(() -> Users.getUser(any(String.class)), never());
    }

    /** XNAT treats a mapping whose account was removed as no mapping, and lets the account be made again. */
    @Test
    public void aMappingWhoseAccountWasRemovedIsUnmapped() {
        mapped();
        users.when(() -> Users.getUser(XNAT_LOGIN)).thenThrow(new UserNotFoundException(XNAT_LOGIN));

        assertThrows(UsernameAuthMappingNotFoundException.class, () -> resolver.resolveExisting(USERNAME, PROVIDER));
    }

    @Test
    public void aMappedAccountThatFailsToLoadIsUnavailableRatherThanUnmapped() {
        mapped();
        final UserInitException failed = new UserInitException("Unable to acquire JDBC Connection");
        users.when(() -> Users.getUser(XNAT_LOGIN)).thenThrow(failed);

        final AccountUnavailableException thrown =
                assertThrows(AccountUnavailableException.class, () -> resolver.resolveExisting(USERNAME, PROVIDER));
        assertSame(failed, thrown.getCause());
    }

    @Test
    public void aMappingThatCannotBeLookedUpIsUnavailableRatherThanUnmapped() {
        final RuntimeException databaseDown = new IllegalStateException("Could not open Hibernate Session for transaction");
        when(userAuthService.getUserByNameAndAuth(USERNAME, XdatUserAuthService.OPENID, PROVIDER)).thenThrow(databaseDown);

        final AccountUnavailableException thrown =
                assertThrows(AccountUnavailableException.class, () -> resolver.resolveExisting(USERNAME, PROVIDER));
        assertSame(databaseDown, thrown.getCause());
    }
}

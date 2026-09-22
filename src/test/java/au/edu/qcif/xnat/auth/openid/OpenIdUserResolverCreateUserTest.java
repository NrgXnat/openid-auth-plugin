package au.edu.qcif.xnat.auth.openid;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.junit.MockitoJUnitRunner;
import org.nrg.xdat.entities.XdatUserAuth;
import org.nrg.xdat.security.helpers.Users;
import org.nrg.xdat.security.user.exceptions.UserInitException;
import org.nrg.xdat.services.XdatUserAuthService;
import org.nrg.xdat.turbine.utils.AdminUtils;
import org.nrg.xft.event.EventDetails;
import org.nrg.xft.security.UserI;
import org.springframework.security.core.AuthenticationException;

import java.util.HashMap;
import java.util.Map;

import static au.edu.qcif.xnat.auth.openid.etc.OpenIdAuthConstant.USERNAME_PATTERN;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.mockito.Mockito.withSettings;

/**
 * Unit tests for {@link OpenIdUserResolver#createUser}, covering what happens when two providers
 * resolve the same {@code usernamePattern} output — i.e. when one person reaches XNAT through two
 * OpenID providers and both derive the same login.
 *
 * <p><b>Why this matters.</b> {@code createUser} builds a fresh user object and hands it, with the
 * new {@link XdatUserAuth} mapping, to {@code Users.save}. XNAT only persists that mapping on its
 * new-user branch: {@code XDATUserMgmtServiceImpl.save} looks the login up first and calls
 * {@code getXdatUserAuthService().create(newUserAuth)} <em>only</em> when no account exists
 * (XDATUserMgmtServiceImpl:225-244). When the account is already there it takes the update branch
 * and the mapping is silently dropped — so {@code resolveExisting} never succeeds for the second
 * provider and every request re-enters {@code createUser}.</p>
 *
 * <p>The shipped sample configurations hide this: they all default {@code usernamePattern} to
 * {@code [providerId]_[sub]}, which is provider-scoped, so two providers never collide on a login.
 * Deployments that key on a real-world identity instead (for example {@code [upn]}) do collide as
 * soon as a second provider is enabled.</p>
 *
 * <p><b>What the resolver does about it.</b> It refuses to run creation at all against a login that is
 * already taken, rather than attaching to whatever account holds that name. Both would stop the
 * re-provisioning, but attaching on a bare login match would take over an account regardless of which
 * provider or authentication method created it; {@code linkExisting} exists for that case and requires a
 * named {@code sourceProvider} so it stays a decision. Refusing also protects the account itself —
 * the update branch would otherwise overwrite its name and email and reset {@code enabled} and
 * {@code verified} from this provider's {@code auto.*} settings, silently re-enabling an account
 * somebody had deliberately disabled.</p>
 *
 * <p>These tests use a mocked {@code Users} rather than a live XNAT, so they pin the resolver's side of
 * the contract. Which downstream symptom a real instance would have shown (re-provisioning on every
 * request, or a failure inside the workflow bookkeeping) no longer matters, since neither is now
 * reachable.</p>
 */
@RunWith(MockitoJUnitRunner.class)
public class OpenIdUserResolverCreateUserTest {

    private static final String FIRST_PROVIDER  = "keycloak";
    private static final String SECOND_PROVIDER = "auth0";

    /** Both providers key on the same claim, so both resolve to this login. */
    private static final String LOGIN = "jsmith";

    @Mock private OpenIdAuthPlugin      plugin;
    @Mock private XdatUserAuthService   userAuthService;

    @Test
    public void refusesToCreateWhenTheXnatLoginIsAlreadyTaken() {
        try (MockedStatic<Users> users = staticUsers();
             MockedStatic<AdminUtils> admin = staticAdminUtils()) {

            // The first provider created this account on an earlier login.
            final UserI existing = mock(UserI.class);
            users.when(() -> Users.getUser(LOGIN)).thenReturn(existing);

            try {
                resolver().createUser(SECOND_PROVIDER, details(SECOND_PROVIDER));
                fail("expected creation to be refused for a login that already exists");
            } catch (final AuthenticationException expected) {
                assertTrue(expected.getMessage().contains("already uses the login"));
            }

            // Nothing may be written on the way out. The save is the dangerous one: reached with an
            // existing login it overwrites that account and resets enabled/verified from this
            // provider's auto.* settings.
            users.verify(() -> Users.save(any(UserI.class), any(UserI.class), any(XdatUserAuth.class),
                    anyBoolean(), any(EventDetails.class)), never());
            verify(userAuthService, never()).create(any(XdatUserAuth.class));
            admin.verifyNoInteractions();
        }
    }

    @Test
    public void leavesTheMappingToSaveWhenTheAccountIsNew() {
        try (MockedStatic<Users> users = staticUsers();
             MockedStatic<AdminUtils> ignored = staticAdminUtils()) {

            // No account yet: save() takes its new-user branch and registers the mapping itself,
            // so registering it here as well would duplicate it.
            users.when(() -> Users.getUser(LOGIN)).thenReturn(null);

            resolver().createUser(FIRST_PROVIDER, details(FIRST_PROVIDER));

            verify(userAuthService, never()).create(any(XdatUserAuth.class));
        }
    }

    @Test
    public void refusesWhenItCannotTellWhetherTheLoginIsTaken() {
        try (MockedStatic<Users> users = staticUsers();
             MockedStatic<AdminUtils> ignored = staticAdminUtils()) {

            // Users.getUser throws for two different reasons: the account does not exist, or it could
            // not be loaded. Only the first means the login is free. Reading the second as free walks
            // into the overwrite this guard exists to prevent, so it has to refuse instead.
            users.when(() -> Users.getUser(LOGIN)).thenThrow(new UserInitException("could not load"));

            try {
                resolver().createUser(FIRST_PROVIDER, details(FIRST_PROVIDER));
                fail("a login whose status could not be determined must not be treated as free");
            } catch (final AuthenticationException expected) {
                assertTrue(expected.getMessage().toLowerCase().contains("already in use"));
            }
            users.verify(() -> Users.save(any(UserI.class), any(UserI.class), anyBoolean(), any(EventDetails.class)),
                         never());
        }
    }

    private OpenIdUserResolver resolver() {
        return new OpenIdUserResolver(plugin, userAuthService);
    }

    /**
     * A user-details object whose {@code usernamePattern} resolves to {@link #LOGIN} whichever
     * provider it came from — the collision this class is about.
     */
    private OpenIdConnectUserDetails details(final String providerId) {
        when(plugin.getProperty(providerId, USERNAME_PATTERN)).thenReturn("[preferred_username]");
        final Map<String, Object> claims = new HashMap<>();
        claims.put("preferred_username", LOGIN);
        return new OpenIdConnectUserDetails(providerId, claims, null, plugin);
    }

    /**
     * Lenient because each test exercises one branch of {@code createUser} and leaves the other
     * branch's stubs unused; the assertions, not stub usage, are what these tests are checking.
     */
    private MockedStatic<Users> staticUsers() {
        // Build every mock before the static stubbing opens: creating one inside an in-progress
        // when(...) is nested stubbing, which Mockito rejects and which leaks the static mock
        // into the next test.
        final UserI created = newUserNamed();
        final UserI admin   = mock(UserI.class);

        final MockedStatic<Users> users = mockStatic(Users.class, withSettings().lenient());
        users.when(() -> Users.isValidUsername(anyString())).thenReturn(true);
        users.when(Users::getAdminUser).thenReturn(admin);
        users.when(Users::createUser).thenReturn(created);
        return users;
    }

    /** Account creation notifies by email; nothing here should try to send one. */
    private MockedStatic<AdminUtils> staticAdminUtils() {
        return mockStatic(AdminUtils.class, withSettings().lenient());
    }

    /** A blank user object that reports {@link #LOGIN} once the resolver has set it. */
    private static UserI newUserNamed() {
        final UserI user = mock(UserI.class);
        when(user.getLogin()).thenReturn(LOGIN);
        return user;
    }
}

package au.edu.qcif.xnat.auth.openid;

import au.edu.qcif.xnat.auth.openid.gate.AuthPath;
import au.edu.qcif.xnat.auth.openid.service.KeystoreService;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.junit.MockitoJUnitRunner;
import org.nrg.xdat.exceptions.UsernameAuthMappingNotFoundException;
import org.nrg.xdat.preferences.SiteConfigPreferences;
import org.nrg.xdat.services.XdatUserAuthService;
import org.nrg.xdat.turbine.utils.TurbineUtils;
import org.nrg.xft.security.UserI;
import org.springframework.security.authentication.AuthenticationEventPublisher;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.core.AuthenticationException;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.Collections;

import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.contains;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * The decision matrix for an interactive login whose identity has no
 * {@code (auth_user, openid, providerId)} mapping yet. Three outcomes are possible and their
 * precedence is the point of these tests: link to an account another provider already maps, else
 * create a new one if {@code forceUserCreate} is set, else divert to the account merge page.
 *
 * <p>Precedence matters in both directions. Linking must win over creation, or someone who already has
 * an account is handed a second, permissionless one. And linking must win over the merge page, because
 * that page asks for the XNAT account's password — which an account provisioned by this plugin does not
 * have, making it a dead end for exactly the people linking exists to serve.</p>
 *
 * <p>The private decision method is invoked directly (the harness pattern used elsewhere in these
 * tests) so the branches can be driven without an OAuth2 exchange. {@code TurbineUtils} is stubbed only
 * where the merge-page redirect needs it.</p>
 */
@RunWith(MockitoJUnitRunner.class)
public class OpenIdConnectFilterMissingMappingTest {

    private static final String PROVIDER = "partner";
    private static final String USERNAME = "alice@example.org";

    @Mock private OpenIdAuthPlugin             plugin;
    @Mock private AuthenticationEventPublisher eventPublisher;
    @Mock private SiteConfigPreferences        siteConfigPreferences;
    @Mock private KeystoreService              keystoreService;
    @Mock private OpenIdUserResolver           userResolver;

    private OpenIdConnectFilter        filter;
    private OpenIdConnectUserDetails   user;
    private HttpServletRequest         request;
    private HttpServletResponse        response;

    @Before
    public void setUp() {
        lenient().when(plugin.getRedirectUri()).thenReturn("/openid/callback");
        lenient().when(plugin.getEnabledProviders()).thenReturn(Collections.singletonList(PROVIDER));
        filter = new OpenIdConnectFilter(plugin, eventPublisher, siteConfigPreferences, keystoreService, userResolver);

        user = mock(OpenIdConnectUserDetails.class);
        lenient().when(user.getUsername()).thenReturn(USERNAME);
        lenient().when(user.getEmail()).thenReturn("alice@example.org");

        request = mock(HttpServletRequest.class);
        response = mock(HttpServletResponse.class);
        lenient().when(request.getSession()).thenReturn(mock(HttpSession.class));
    }

    /** Invokes the private missing-mapping decision, unwrapping reflection's exception wrapper. */
    private UserI decide() throws Throwable {
        final Method method = OpenIdConnectFilter.class.getDeclaredMethod("resolveOnMissingMapping",
                String.class, OpenIdConnectUserDetails.class, String.class,
                UsernameAuthMappingNotFoundException.class, HttpServletRequest.class, HttpServletResponse.class);
        method.setAccessible(true);
        final UsernameAuthMappingNotFoundException notFound =
                new UsernameAuthMappingNotFoundException(USERNAME, XdatUserAuthService.OPENID, PROVIDER, null, null, null);
        try {
            return (UserI) method.invoke(filter, PROVIDER, user, USERNAME, notFound, request, response);
        } catch (final InvocationTargetException e) {
            throw e.getCause();
        }
    }

    private void forceUserCreate(final boolean enabled) {
        lenient().when(plugin.getProperty(PROVIDER, "forceUserCreate")).thenReturn(Boolean.toString(enabled));
    }

    private void linkingFinds(final UserI account) {
        when(userResolver.linkExistingIfConfigured(PROVIDER, AuthPath.ID_TOKEN, USERNAME)).thenReturn(account);
    }

    // ---- linking wins, whatever else is configured ----------------------------------------------

    @Test
    public void linkedAccountIsUsedWhenForceUserCreateIsOff() throws Throwable {
        final UserI existing = mock(UserI.class);
        forceUserCreate(false);
        linkingFinds(existing);

        assertSame(existing, decide());
        verify(userResolver, never()).createUser(anyString(), org.mockito.ArgumentMatchers.any());
        // Neither of the other two outcomes may leave a trace: no merge-page redirect, and no session
        // mutation on the way past it.
        verify(response, never()).sendRedirect(anyString());
        verify(request, never()).getSession();
    }

    @Test
    public void linkedAccountWinsOverForceUserCreate() throws Throwable {
        // Otherwise someone who already has an account is handed a second, permissionless one.
        final UserI existing = mock(UserI.class);
        forceUserCreate(true);
        linkingFinds(existing);

        assertSame(existing, decide());
        verify(userResolver, never()).createUser(anyString(), org.mockito.ArgumentMatchers.any());
    }

    // ---- nothing to link: create, or divert ------------------------------------------------------

    @Test
    public void createsAnAccountWhenNothingLinksAndForceUserCreateIsOn() throws Throwable {
        final UserI created = mock(UserI.class);
        forceUserCreate(true);
        linkingFinds(null);
        when(userResolver.createUser(PROVIDER, user)).thenReturn(created);

        assertSame(created, decide());
        verify(response, never()).sendRedirect(anyString());
    }

    @Test
    public void divertsToTheMergePageWhenNothingLinksAndForceUserCreateIsOff() throws Throwable {
        forceUserCreate(false);
        linkingFinds(null);

        try (final MockedStatic<TurbineUtils> turbine = mockStatic(TurbineUtils.class)) {
            turbine.when(TurbineUtils::GetFullServerPath).thenReturn("https://xnat.example");

            assertNull("null tells the caller it has been redirected", decide());
        }

        verify(response).sendRedirect(contains("RegisterExternalLogin.vm"));
        verify(userResolver, never()).createUser(anyString(), org.mockito.ArgumentMatchers.any());
    }

    @Test
    public void divertingStashesTheIdentityForTheMergePage() throws Throwable {
        // The merge page reads this attribute to prefill who is being linked; without it the page cannot
        // tell the user which external identity they are attaching.
        final HttpSession session = mock(HttpSession.class);
        when(request.getSession()).thenReturn(session);
        forceUserCreate(false);
        linkingFinds(null);

        try (final MockedStatic<TurbineUtils> turbine = mockStatic(TurbineUtils.class)) {
            turbine.when(TurbineUtils::GetFullServerPath).thenReturn("https://xnat.example");
            decide();
        }

        verify(session).setAttribute(
                org.mockito.ArgumentMatchers.eq(UsernameAuthMappingNotFoundException.class.getSimpleName()),
                org.mockito.ArgumentMatchers.any(UsernameAuthMappingNotFoundException.class));
    }

    // ---- linking disabled is indistinguishable from linking finding nothing ----------------------

    @Test
    public void linkingDisabledStillDivertsToTheMergePage() throws Throwable {
        // linkExistingIfConfigured returns null both when off and when it matched nothing, so the
        // downstream behaviour must be identical — an unconfigured site keeps the old flow exactly.
        forceUserCreate(false);
        linkingFinds(null);

        try (final MockedStatic<TurbineUtils> turbine = mockStatic(TurbineUtils.class)) {
            turbine.when(TurbineUtils::GetFullServerPath).thenReturn("https://xnat.example");
            assertNull(decide());
        }
        verify(response).sendRedirect(contains("RegisterExternalLogin.vm"));
    }

    // ---- failures propagate rather than silently downgrading ------------------------------------

    @Test
    public void aFailedLinkDoesNotFallThroughToCreation() throws Throwable {
        // A link that should have succeeded must not quietly become a duplicate account.
        forceUserCreate(true);
        when(userResolver.linkExistingIfConfigured(PROVIDER, AuthPath.ID_TOKEN, USERNAME))
                .thenThrow(new AuthenticationServiceException("save failed"));

        try {
            decide();
            fail("expected the link failure to propagate");
        } catch (final AuthenticationException expected) {
            assertTrue(expected.getMessage().contains("save failed"));
        }
        verify(userResolver, never()).createUser(anyString(), org.mockito.ArgumentMatchers.any());
        verify(response, never()).sendRedirect(anyString());
    }
}

package au.edu.qcif.xnat.auth.openid.gate;

import au.edu.qcif.xnat.auth.openid.OpenIdAuthPlugin;
import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import com.nimbusds.jwt.JWTClaimsSet;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.junit.MockitoJUnitRunner;
import org.nrg.xdat.XDAT;
import org.nrg.xdat.preferences.SiteConfigPreferences;
import org.nrg.xdat.security.helpers.Roles;
import org.nrg.xdat.security.helpers.Users;
import org.nrg.xdat.security.services.RoleRepositoryServiceI.RoleDefinitionI;
import org.nrg.xft.security.UserI;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.Set;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.when;

@RunWith(MockitoJUnitRunner.class)
public class RoleSyncTest {

    private static final String PROVIDER = "keycloak";
    private static final String MAPPINGS =
            "resource_access.xnat.roles:xnat-admin=Administrator, resource_access.datasets.roles:datasets-iq-admin=XnatIQ";
    private static final String ADMIN_MAPPING = "resource_access.xnat.roles:xnat-admin=Administrator";

    @Mock private OpenIdAuthPlugin plugin;

    private final Map<String, String> props = new HashMap<>();
    /** Settings outside the provider's own namespace, as written in the properties file. */
    private final Properties otherSettings = new Properties();
    private final FakeStore store = new FakeStore();
    private final UserI user = mock(UserI.class);

    @Before
    public void setUp() {
        lenient().when(plugin.getProperty(eq(PROVIDER), anyString()))
                .thenAnswer(invocation -> props.get(invocation.getArgument(1)));
        lenient().when(plugin.getEnabledProviders()).thenReturn(Collections.singletonList(PROVIDER));
        lenient().when(plugin.getProps()).thenAnswer(invocation -> settings());
        lenient().when(user.getUsername()).thenReturn("jane");
        props.put("roleSync.enabled", "true");
        props.put("roleSync.mappings", MAPPINGS);
    }

    @Test
    public void grantsMappedRoleWhenTokenCarriesIt() {
        final List<ILoggingEvent> events = logDuring(() ->
                assertSame(store.reloaded, sync(AuthPath.ID_TOKEN, clientRoles("xnat", "xnat-access", "xnat-admin"))));

        assertEquals(Collections.singletonList("+Administrator"), store.changes);
        assertEquals(Collections.singletonList("Role sync for provider 'keycloak' on the idToken path gave user 'jane' "
                + "the XNAT role 'Administrator'"), messagesAt(Level.INFO, events));
    }

    @Test
    public void removesMappedRoleWhenClaimPathPresentWithoutTheRole() {
        store.roles.add("Administrator");

        final List<ILoggingEvent> events = logDuring(() ->
                assertSame(store.reloaded, sync(AuthPath.ID_TOKEN, clientRoles("xnat", "xnat-access"))));

        assertEquals(Collections.singletonList("-Administrator"), store.changes);
        assertEquals(Collections.singletonList("Role sync for provider 'keycloak' on the idToken path removed the XNAT "
                + "role 'Administrator' from user 'jane'"), messagesAt(Level.INFO, events));
    }

    @Test
    public void aFailedChangeToOneRoleStillSyncsTheOthers() {
        props.put("roleSync.mappings",
                "resource_access.datasets.roles:datasets-iq-admin=XnatIQ, resource_access.xnat.roles:xnat-admin=Administrator");
        store.roles.add("XnatIQ");
        store.failRemove = true;
        final Map<String, Object> access = new HashMap<>();
        access.put("datasets", Collections.singletonMap("roles", Arrays.asList("datasets-user")));
        access.put("xnat", Collections.singletonMap("roles", Arrays.asList("xnat-access", "xnat-admin")));

        sync(AuthPath.BEARER, Collections.singletonMap("resource_access", access));

        assertEquals(Collections.singletonList("+Administrator"), store.changes);
        assertTrue(store.roles.contains("XnatIQ"));
    }

    @Test
    public void leavesRoleAloneWhenTokenLacksItsClaimPath() {
        store.roles.add("XnatIQ");

        final UserI result = sync(AuthPath.ID_TOKEN, clientRoles("xnat", "xnat-access"));

        assertTrue(store.changes.isEmpty());
        assertSame(user, result);
    }

    @Test
    public void writesNothingWhenRolesAlreadyMatch() {
        store.roles.add("XnatIQ");

        final UserI result = sync(AuthPath.BEARER, clientRoles("datasets", "datasets-user", "datasets-iq-admin"));

        assertTrue(store.changes.isEmpty());
        assertSame(user, result);
    }

    @Test
    public void leavesUnmappedRolesAlone() {
        store.roles.add("SomethingElse");

        sync(AuthPath.ID_TOKEN, clientRoles("xnat", "xnat-access"));

        assertTrue(store.changes.isEmpty());
    }

    @Test
    public void doesNothingWhenDisabled() {
        props.remove("roleSync.enabled");

        final UserI result = sync(AuthPath.ID_TOKEN, clientRoles("xnat", "xnat-admin"));

        assertTrue(store.changes.isEmpty());
        assertSame(user, result);
    }

    @Test
    public void pathScopedSettingOverridesShared() {
        props.put("bearer.roleSync.enabled", "false");

        sync(AuthPath.BEARER, clientRoles("xnat", "xnat-admin"));

        assertTrue(store.changes.isEmpty());
    }

    @Test
    public void aPathScopedMappingListReplacesTheSharedOne() {
        props.put("roleSync.mappings", "resource_access.xnat.roles:xnat-admin=XnatIQ");
        props.put("idToken.roleSync.mappings", "groups:xnat-admin=Administrator");
        final Map<String, Object> claims = clientRoles("xnat", "xnat-access", "xnat-admin");
        claims.put("groups", Arrays.asList("xnat-access", "xnat-admin"));
        final FakeStore bearer = new FakeStore();

        sync(AuthPath.ID_TOKEN, claims);
        new RoleSync(plugin, bearer).apply(PROVIDER, AuthPath.BEARER, TokenContext.of(token(claims)), user);

        assertEquals("the ID-token list replaces the shared one", Collections.singletonList("+Administrator"), store.changes);
        assertEquals("the bearer path uses the shared list", Collections.singletonList("+XnatIQ"), bearer.changes);
    }

    @Test
    public void failedChangeGrantsNothingAndKeepsUser() {
        store.failAdd = true;

        final List<ILoggingEvent> warnings =
                warningsDuring(() -> assertSame(user, sync(AuthPath.ID_TOKEN, clientRoles("xnat", "xnat-admin"))));

        assertTrue(store.roles.isEmpty());
        assertEquals(1, warnings.size());
    }

    @Test
    public void warnsOnceWhenAChangeKeepsFailing() {
        // A failed change is tried again at every sign-in, which on the bearer path is every request.
        store.roles.add("Administrator");
        store.failRemove = true;
        final RoleSync roleSync = new RoleSync(plugin, store);
        final TokenContext token = TokenContext.of(token(clientRoles("xnat", "xnat-access")));

        final List<ILoggingEvent> events = logDuring(() -> {
            roleSync.apply(PROVIDER, AuthPath.BEARER, token, user);
            roleSync.apply(PROVIDER, AuthPath.BEARER, token, named("john"));
        });

        assertEquals(Collections.singletonList("Role sync for provider 'keycloak' on the bearer path could not remove "
                + "the XNAT role 'Administrator' for user 'jane': refused; later failures of this kind are logged at "
                + "DEBUG"), messagesAt(Level.WARN, events));
        assertTrue(messagesAt(Level.DEBUG, events).contains("Role sync for provider 'keycloak' on the bearer path could "
                + "not remove the XNAT role 'Administrator' for user 'john': refused"));
    }

    @Test
    public void warnsSeparatelyForEachChangeThatFails() {
        props.put("roleSync.mappings", ADMIN_MAPPING);
        store.failAdd = true;
        store.failRemove = true;
        final RoleSync roleSync = new RoleSync(plugin, store);

        final List<ILoggingEvent> warnings = warningsDuring(() -> {
            roleSync.apply(PROVIDER, AuthPath.BEARER, TokenContext.of(token(clientRoles("xnat", "xnat-admin"))), user);
            store.roles.add("Administrator");
            roleSync.apply(PROVIDER, AuthPath.BEARER, TokenContext.of(token(clientRoles("xnat", "xnat-access"))), user);
        });

        assertEquals(2, warnings.size());
    }

    @Test
    public void aFailedRemovalKeepsTheRoleAndTheUser() {
        store.roles.add("Administrator");
        store.failRemove = true;

        final UserI result = sync(AuthPath.BEARER, clientRoles("xnat", "xnat-access"));

        assertTrue(store.roles.contains("Administrator"));
        assertSame(user, result);
    }

    @Test
    public void keepsTheSignedInUserWhenTheReloadFails() {
        store.reloadFails = true;

        final UserI result = sync(AuthPath.ID_TOKEN, clientRoles("xnat", "xnat-access", "xnat-admin"));

        assertEquals(Collections.singletonList("+Administrator"), store.changes);
        assertSame(user, result);
    }

    @Test
    public void anAddXnatDidNotMakeChangesNothingAndIsLoggedAsInformation() {
        store.noChange = true;

        final List<ILoggingEvent> events = logDuring(() ->
                assertSame(user, sync(AuthPath.BEARER, clientRoles("xnat", "xnat-access", "xnat-admin"))));

        assertTrue(store.roles.isEmpty());
        assertEquals(1, messagesAt(Level.INFO, events).size());
        assertTrue(messagesAt(Level.WARN, events).isEmpty());
    }

    @Test
    public void aRemovalXnatDidNotMakeChangesNothingAndIsLoggedAsInformation() {
        store.roles.add("Administrator");
        store.noChange = true;

        final List<ILoggingEvent> events = logDuring(() ->
                assertSame(user, sync(AuthPath.BEARER, clientRoles("xnat", "xnat-access"))));

        assertTrue(store.roles.contains("Administrator"));
        assertEquals(1, messagesAt(Level.INFO, events).size());
        assertTrue(messagesAt(Level.WARN, events).isEmpty());
    }

    @Test
    public void aNullUserIsReturnedUntouched() {
        final UserI result = new RoleSync(plugin, store)
                .apply(PROVIDER, AuthPath.ID_TOKEN, TokenContext.of(token(clientRoles("xnat", "xnat-admin"))), null);

        assertNull(result);
        assertTrue(store.changes.isEmpty());
    }

    @Test
    public void anyMatchingMappingKeepsTheRole() {
        props.put("roleSync.mappings", "resource_access.xnat.roles:xnat-admin=Administrator,realm_access.roles:site-admin=Administrator");
        store.roles.add("Administrator");
        final Map<String, Object> claims = clientRoles("xnat", "xnat-access");
        claims.put("realm_access", Collections.singletonMap("roles", Arrays.asList("site-admin")));

        sync(AuthPath.ID_TOKEN, claims);

        assertTrue(store.changes.isEmpty());
    }

    @Test
    public void oneTokenRoleCanGrantTwoXnatRoles() {
        props.put("roleSync.mappings", ADMIN_MAPPING + ",resource_access.xnat.roles:xnat-admin=XnatIQ");

        sync(AuthPath.BEARER, clientRoles("xnat", "xnat-access", "xnat-admin"));

        assertEquals(new HashSet<>(Arrays.asList("+Administrator", "+XnatIQ")), new HashSet<>(store.changes));
    }

    @Test
    public void syncsEachRoleIndependently() {
        store.roles.add("Administrator");
        store.roles.add("XnatIQ");
        final Map<String, Object> access = new HashMap<>();
        access.put("xnat", Collections.singletonMap("roles", Arrays.asList("xnat-access", "xnat-admin")));
        access.put("datasets", Collections.singletonMap("roles", Arrays.asList("datasets-user")));

        sync(AuthPath.BEARER, Collections.singletonMap("resource_access", access));

        assertEquals(Collections.singletonList("-XnatIQ"), store.changes);
    }

    @Test
    public void warnsOnceAboutAMappingWhoseClaimCannotHoldRoles() {
        props.put("roleSync.mappings", "resource_access.xnat:xnat-admin=Administrator");
        final RoleSync roleSync = new RoleSync(plugin, store);
        final TokenContext token = TokenContext.of(token(clientRoles("xnat", "xnat-access", "xnat-admin")));

        final List<ILoggingEvent> warnings = warningsDuring(() -> {
            roleSync.apply(PROVIDER, AuthPath.BEARER, token, user);
            roleSync.apply(PROVIDER, AuthPath.BEARER, token, user);
        });

        assertEquals(1, warnings.size());
        assertTrue(warnings.get(0).getFormattedMessage(),
                warnings.get(0).getFormattedMessage().contains("'resource_access.xnat:xnat-admin=Administrator'"));
    }

    @Test
    public void warnsOnceForEachMappingWhoseClaimCannotHoldRoles() {
        props.put("roleSync.mappings", "resource_access:xnat-admin=Administrator, resource_access.xnat:xnat-admin=Administrator");
        final RoleSync roleSync = new RoleSync(plugin, store);
        final TokenContext token = TokenContext.of(token(clientRoles("xnat", "xnat-access", "xnat-admin")));

        final List<ILoggingEvent> warnings = warningsDuring(() -> {
            roleSync.apply(PROVIDER, AuthPath.BEARER, token, user);
            roleSync.apply(PROVIDER, AuthPath.BEARER, token, user);
        });

        assertEquals(2, warnings.size());
    }

    @Test
    public void removesTheRoleWhenTheClaimIsAnEmptyList() {
        store.roles.add("Administrator");

        sync(AuthPath.BEARER, clientRoles("xnat"));

        assertEquals(Collections.singletonList("-Administrator"), store.changes);
    }

    @Test
    public void leavesTheRoleWhenTheClaimIsNull() {
        store.roles.add("Administrator");
        final Map<String, Object> claims = new HashMap<>();
        claims.put("resource_access", Collections.singletonMap("xnat", Collections.singletonMap("roles", null)));

        sync(AuthPath.BEARER, claims);

        assertTrue(store.changes.isEmpty());
    }

    @Test
    public void neverRemovesARoleFromAProtectedAccount() {
        store.roles.add("Administrator");
        store.protectedAccount = true;

        final UserI result = sync(AuthPath.ID_TOKEN, clientRoles("xnat", "xnat-access"));

        assertTrue(store.changes.isEmpty());
        assertSame(user, result);
    }

    @Test
    public void stillAddsRolesToAProtectedAccount() {
        store.protectedAccount = true;

        sync(AuthPath.BEARER, clientRoles("datasets", "datasets-iq-admin"));

        assertEquals(Collections.singletonList("+XnatIQ"), store.changes);
    }

    @Test
    public void keepsTheRoleWhenItCannotTellWhetherTheAccountIsProtected() {
        store.roles.add("Administrator");
        store.protectedAccountFails = true;

        final UserI result = sync(AuthPath.BEARER, clientRoles("xnat", "xnat-access"));

        assertTrue(store.roles.contains("Administrator"));
        assertSame(user, result);
    }

    @Test
    public void warnsOnlyOnceThatAProtectedAccountKeepsARole() {
        store.roles.add("Administrator");
        store.protectedAccount = true;
        final RoleSync roleSync = new RoleSync(plugin, store);
        final TokenContext token = TokenContext.of(token(clientRoles("xnat", "xnat-access")));

        final List<ILoggingEvent> warnings = warningsDuring(() -> {
            roleSync.apply(PROVIDER, AuthPath.ID_TOKEN, token, user);
            roleSync.apply(PROVIDER, AuthPath.ID_TOKEN, token, user);
        });

        assertEquals(1, warnings.size());
        assertTrue(store.roles.contains("Administrator"));
    }

    @Test
    public void warnsOnceForEachRoleAProtectedAccountKeeps() {
        store.roles.add("Administrator");
        store.roles.add("XnatIQ");
        store.protectedAccount = true;
        final RoleSync roleSync = new RoleSync(plugin, store);
        final Map<String, Object> access = new HashMap<>();
        access.put("xnat", Collections.singletonMap("roles", Arrays.asList("xnat-access")));
        access.put("datasets", Collections.singletonMap("roles", Arrays.asList("datasets-user")));
        final TokenContext token = TokenContext.of(token(Collections.singletonMap("resource_access", access)));

        final List<ILoggingEvent> warnings = warningsDuring(() -> {
            roleSync.apply(PROVIDER, AuthPath.BEARER, token, user);
            roleSync.apply(PROVIDER, AuthPath.BEARER, token, user);
        });

        assertEquals(2, warnings.size());
    }

    @Test
    public void appliesTheRestWithoutAWarningWhenAnEntryIsMalformed() {
        props.put("roleSync.mappings", "nocolon=Role, " + MAPPINGS);

        final List<ILoggingEvent> warnings =
                warningsDuring(() -> sync(AuthPath.BEARER, clientRoles("xnat", "xnat-access", "xnat-admin")));

        assertEquals(Collections.singletonList("+Administrator"), store.changes);
        assertTrue("a malformed entry is reported at startup, not at each sign-in", warnings.isEmpty());
    }

    @Test
    public void grantsAnXnatRoleWithASpaceInItsName() {
        props.put("roleSync.mappings", "resource_access.xnat.roles:xnat-admin=Data Manager");

        sync(AuthPath.BEARER, clientRoles("xnat", "xnat-admin"));

        assertEquals(Collections.singletonList("+Data Manager"), store.changes);
    }

    @Test
    public void aRejectedMappingNeitherGivesNorRemovesItsRole() {
        store.roles.add("Administrator");
        props.put("roleSync.mappings", "resource_access..xnat.roles:xnat-admin=Administrator, "
                + "resource_access.xnat.roles:xnat-admin=XnatIQ=Extra");

        sync(AuthPath.BEARER, clientRoles("xnat", "xnat-access"));

        assertTrue(store.changes.isEmpty());
        assertEquals(Collections.singleton("Administrator"), store.roles);
    }

    @Test
    public void saysWhyAMappingIsIgnored() {
        props.put("roleSync.mappings", "nocolon=Role, " + ADMIN_MAPPING);

        assertEquals(Collections.singletonList("Role sync for provider 'keycloak' on the idToken path ignores the "
                + "mapping 'nocolon=Role': it has no ':' after its claim path"), messagesAt(Level.WARN, report()));
    }

    @Test
    public void reportsEachPathsOwnMistakes() {
        props.put("roleSync.mappings", "nocolon=Role, " + MAPPINGS);
        props.put("idToken.roleSync.mappings", "path:role=, groups:xnat-admin=Administrator");

        assertEquals(Arrays.asList(
                "Role sync for provider 'keycloak' on the idToken path ignores the mapping 'path:role=': it has nothing "
                        + "after its '='",
                "Role sync for provider 'keycloak' on the bearer path ignores the mapping 'nocolon=Role': it has no ':' "
                        + "after its claim path"),
                messagesAt(Level.WARN, report(PROVIDER)));
    }

    @Test
    public void notesMappingsWhileRoleSyncIsOff() {
        props.remove("roleSync.enabled");
        props.put("roleSync.mappings", "nocolon=Role");

        final List<ILoggingEvent> events = report();

        assertEquals(Collections.singletonList("Role sync for provider 'keycloak' on the idToken path is off, though "
                + "roleSync.mappings is set"), messagesAt(Level.INFO, events));
        assertTrue(messagesAt(Level.WARN, events).isEmpty());
    }

    @Test
    public void reportsNothingWhenRoleSyncIsNotSet() {
        props.clear();

        assertTrue(report(PROVIDER).isEmpty());
    }

    @Test
    public void reportsNothingAtSignInWhenRoleSyncIsNotSet() {
        props.clear();

        assertTrue(logDuring(() -> sync(AuthPath.BEARER, clientRoles("xnat", "xnat-admin"))).isEmpty());
    }

    @Test
    public void summarisesWhatRoleSyncWillManage() {
        final List<ILoggingEvent> events = report();

        assertEquals(Collections.singletonList("Role sync for provider 'keycloak' on the idToken path is on, with 2 "
                + "mappings for the XNAT roles [Administrator, XnatIQ]"), messagesAt(Level.INFO, events));
        assertTrue(messagesAt(Level.WARN, events).isEmpty());
    }

    @Test
    public void countsASingleMapping() {
        props.put("roleSync.mappings", ADMIN_MAPPING);

        assertEquals(Collections.singletonList("Role sync for provider 'keycloak' on the idToken path is on, with 1 "
                + "mapping for the XNAT roles [Administrator]"), messagesAt(Level.INFO, report()));
    }

    @Test
    public void reportsTheBearerPathOnlyForTheProvidersItServes() {
        assertEquals(1, messagesAt(Level.INFO, report()).size());
        assertEquals(2, messagesAt(Level.INFO, report(PROVIDER)).size());
    }

    @Test
    public void acceptsTrueInAnyCase() {
        props.put("roleSync.enabled", "TRUE");

        final List<ILoggingEvent> events = report();

        assertEquals(1, messagesAt(Level.INFO, events).size());
        assertTrue(messagesAt(Level.WARN, events).isEmpty());
    }

    @Test
    public void acceptsFalseInAnyCase() {
        props.put("roleSync.enabled", "False");

        assertTrue(messagesAt(Level.WARN, report()).isEmpty());
    }

    @Test
    public void warnsThatAnEnabledValueOtherThanTrueOrFalseTurnsRoleSyncOff() {
        props.put("roleSync.enabled", "yes");

        assertEquals(Collections.singletonList("Role sync for provider 'keycloak' on the idToken path is off: "
                + "roleSync.enabled is 'yes', and only true or false is accepted"), messagesAt(Level.WARN, report()));
    }

    @Test
    public void showsATrailingSpaceInTheEnabledValue() {
        props.put("roleSync.enabled", "true ");

        assertEquals(Collections.singletonList("Role sync for provider 'keycloak' on the idToken path is off: "
                + "roleSync.enabled is 'true ', and only true or false is accepted"), messagesAt(Level.WARN, report()));
    }

    @Test
    public void showsAHiddenCharacterInTheEnabledValueAsAnEscape() {
        props.put("roleSync.enabled", "true\u00A0");

        assertEquals(Collections.singletonList("Role sync for provider 'keycloak' on the idToken path is off: "
                + "roleSync.enabled is 'true\\u00A0', and only true or false is accepted"), messagesAt(Level.WARN, report()));
    }

    @Test
    public void warnsWhenRoleSyncIsOnWithoutMappings() {
        props.remove("roleSync.mappings");

        assertEquals(Collections.singletonList("Role sync for provider 'keycloak' on the idToken path is on but has no "
                + "usable mappings, so it does nothing"), messagesAt(Level.WARN, report()));
    }

    @Test
    public void warnsWhenEveryMappingIsRejected() {
        props.put("roleSync.mappings", "nocolon=Role");

        assertEquals(Arrays.asList(
                "Role sync for provider 'keycloak' on the idToken path ignores the mapping 'nocolon=Role': it has no ':' "
                        + "after its claim path",
                "Role sync for provider 'keycloak' on the idToken path is on but has no usable mappings, so it does "
                        + "nothing"), messagesAt(Level.WARN, report()));
    }

    @Test
    public void warnsAboutAnXnatRoleXnatDoesNotDefine() {
        props.put("roleSync.mappings", "resource_access.xnat.roles:xnat-admin=Adminstrator");

        final List<ILoggingEvent> events = report();

        assertEquals(Collections.singletonList("Role sync for provider 'keycloak' on the idToken path will never add "
                + "the XNAT role 'Adminstrator': XNAT does not define it; the role is still removed when the token says "
                + "so"), messagesAt(Level.WARN, events));
        assertEquals(Collections.singletonList("Role sync for provider 'keycloak' on the idToken path is on, with 1 "
                + "mapping for the XNAT roles [Adminstrator (remove only)]"), messagesAt(Level.INFO, events));
    }

    @Test
    public void namesTheDefinedRoleWhenOnlyTheCaseDiffers() {
        props.put("roleSync.mappings", "resource_access.xnat.roles:xnat-admin=administrator");

        assertEquals(Collections.singletonList("Role sync for provider 'keycloak' on the idToken path will never add "
                + "the XNAT role 'administrator': XNAT does not define it (did you mean 'Administrator'?); the role is "
                + "still removed when the token says so"), messagesAt(Level.WARN, report()));
    }

    @Test
    public void acceptsARoleAnotherPluginDefines() {
        store.defined.add("DataSteward");
        props.put("roleSync.mappings", "groups:stewards=DataSteward");

        assertTrue(messagesAt(Level.WARN, report()).isEmpty());
    }

    @Test
    public void warnsThatAPathsRolesWentUncheckedWhenXnatsRolesCannotBeRead() {
        store.definedFails = true;

        final List<ILoggingEvent> events = report();

        assertEquals(Collections.singletonList("Role sync for provider 'keycloak' on the idToken path could not check "
                + "its mapped XNAT roles: XNAT's role list could not be read: no role service"),
                messagesAt(Level.WARN, events));
        assertEquals("the path is still reported", 1, messagesAt(Level.INFO, events).size());
    }

    @Test
    public void warnsThatAPathsRolesWentUncheckedWhenXnatDefinesNoRoles() {
        store.defined.clear();

        final List<ILoggingEvent> events = report();

        assertEquals(Collections.singletonList("Role sync for provider 'keycloak' on the idToken path could not check "
                + "its mapped XNAT roles: XNAT reported no defined roles"), messagesAt(Level.WARN, events));
        assertEquals("the path is still reported", 1, messagesAt(Level.INFO, events).size());
    }

    @Test
    public void doesNotReadXnatsRolesForAPathWithNothingToCheck() {
        store.definedFails = true;
        props.remove("roleSync.mappings");

        assertEquals(Collections.singletonList("Role sync for provider 'keycloak' on the idToken path is on but has no "
                + "usable mappings, so it does nothing"), messagesAt(Level.WARN, report()));
    }

    @Test
    public void warnsAboutAMisspeltRoleSyncSetting() {
        props.put("roleSync.mapping", ADMIN_MAPPING);
        props.put("idtoken.roleSync.enabled", "true");
        otherSettings.setProperty("openid.keycloak.rolesync.enabled", "true");

        assertEquals(Arrays.asList(
                "Role sync ignores the setting 'openid.keycloak.idtoken.roleSync.enabled': role sync settings are "
                        + "openid.<provider>.roleSync.enabled or .mappings, optionally with idToken. or bearer. before "
                        + "roleSync",
                "Role sync ignores the setting 'openid.keycloak.roleSync.mapping': role sync settings are "
                        + "openid.<provider>.roleSync.enabled or .mappings, optionally with idToken. or bearer. before "
                        + "roleSync",
                "Role sync ignores the setting 'openid.keycloak.rolesync.enabled': role sync settings are "
                        + "openid.<provider>.roleSync.enabled or .mappings, optionally with idToken. or bearer. before "
                        + "roleSync"),
                messagesAt(Level.WARN, report()));
    }

    @Test
    public void warnsAboutARoleSyncSettingForAProviderThatIsNotEnabled() {
        otherSettings.setProperty("openid.keyclaok.roleSync.enabled", "true");

        assertEquals(Collections.singletonList("Role sync ignores the setting 'openid.keyclaok.roleSync.enabled': "
                + "'keyclaok' is not an enabled OpenID provider"), messagesAt(Level.WARN, report()));
    }

    @Test
    public void acceptsARoleSyncSettingForAProviderWhoseIdHoldsADot() {
        when(plugin.getEnabledProviders()).thenReturn(Arrays.asList(PROVIDER, "my.idp"));
        otherSettings.setProperty("openid.my.idp.roleSync.enabled", "false");
        otherSettings.setProperty("openid.my.idp.bearer.roleSync.mappings", ADMIN_MAPPING);

        assertTrue(messagesAt(Level.WARN, report()).isEmpty());
    }

    @Test
    public void acceptsEveryFormOfARoleSyncSetting() {
        props.put("bearer.roleSync.enabled", "true");
        props.put("idToken.roleSync.mappings", ADMIN_MAPPING);
        props.put("clientId", "xnat");

        assertTrue(messagesAt(Level.WARN, report(PROVIDER)).isEmpty());
    }

    @Test
    public void neverGivesARoleXnatDoesNotDefine() {
        props.put("roleSync.mappings", "resource_access.xnat.roles:xnat-admin=administrator");
        final RoleSync roleSync = new RoleSync(plugin, store);
        final TokenContext token = TokenContext.of(token(clientRoles("xnat", "xnat-admin")));

        final List<ILoggingEvent> events = logDuring(() -> {
            roleSync.apply(PROVIDER, AuthPath.BEARER, token, user);
            roleSync.apply(PROVIDER, AuthPath.BEARER, token, user);
        });

        assertTrue(store.changes.isEmpty());
        assertTrue("the startup report warns about the mapping; a sign-in only notes it", messagesAt(Level.WARN, events).isEmpty());
        assertEquals(Arrays.asList(
                "Role sync for provider 'keycloak' on the bearer path did not give user 'jane' the XNAT role "
                        + "'administrator': XNAT does not define it",
                "Role sync for provider 'keycloak' on the bearer path did not give user 'jane' the XNAT role "
                        + "'administrator': XNAT does not define it"), messagesAt(Level.DEBUG, events));
    }

    @Test
    public void stillRemovesARoleXnatDoesNotDefine() {
        store.roles.add("Legacy");
        props.put("roleSync.mappings", "resource_access.xnat.roles:xnat-admin=Legacy");

        sync(AuthPath.BEARER, clientRoles("xnat", "xnat-access"));

        assertEquals(Collections.singletonList("-Legacy"), store.changes);
    }

    @Test
    public void givesNoRoleWhenXnatsRolesCannotBeRead() {
        store.definedFails = true;

        final List<ILoggingEvent> events = logDuring(() -> sync(AuthPath.ID_TOKEN, clientRoles("xnat", "xnat-admin")));

        assertTrue(store.changes.isEmpty());
        assertEquals(Collections.singletonList("Role sync for provider 'keycloak' on the idToken path could not add the "
                + "XNAT role 'Administrator' for user 'jane': no role service; later failures of this kind are logged "
                + "at DEBUG"), messagesAt(Level.WARN, events));
    }

    @Test
    public void givesTheRoleWhenXnatDefinesNoRoles() {
        store.defined.clear();

        sync(AuthPath.ID_TOKEN, clientRoles("xnat", "xnat-admin"));

        assertEquals(Collections.singletonList("+Administrator"), store.changes);
    }

    @Test
    public void saysWhyTheSignInFailsWhenTheUsersRolesCannotBeRead() {
        store.rolesFail = true;

        final List<ILoggingEvent> events = logDuring(() -> {
            try {
                sync(AuthPath.ID_TOKEN, clientRoles("xnat", "xnat-admin"));
                fail("the sign-in must fail");
            } catch (final IllegalStateException expected) {
                assertEquals("database down", expected.getMessage());
            }
        });

        assertEquals(Collections.singletonList("Role sync for provider 'keycloak' on the idToken path could not read the "
                + "XNAT roles of user 'jane', so the sign-in fails: database down"), messagesAt(Level.WARN, events));
        assertNull("XNAT's own log has the stack trace", events.get(0).getThrowableProxy());
    }

    @Test
    public void saysAtDebugWhyItLeftARoleAlone() {
        final List<ILoggingEvent> events = logDuring(() -> sync(AuthPath.ID_TOKEN, clientRoles("xnat", "xnat-access")));

        assertEquals(Arrays.asList(
                "Role sync for provider 'keycloak' on the idToken path made no change to the XNAT role 'Administrator' "
                        + "of user 'jane': the user doesn't have it",
                "Role sync for provider 'keycloak' on the idToken path left the XNAT role 'XnatIQ' of user 'jane' as it "
                        + "is: the token doesn't carry its claim path"), messagesAt(Level.DEBUG, events));
    }

    @Test
    public void saysAtDebugThatARoleAlreadyMatches() {
        store.roles.add("Administrator");
        final Map<String, Object> access = new HashMap<>();
        access.put("xnat", Collections.singletonMap("roles", Arrays.asList("xnat-admin")));
        access.put("datasets", Collections.singletonMap("roles", Arrays.asList("datasets-user")));

        final List<ILoggingEvent> events =
                logDuring(() -> sync(AuthPath.BEARER, Collections.singletonMap("resource_access", access)));

        assertEquals(Arrays.asList(
                "Role sync for provider 'keycloak' on the bearer path made no change to the XNAT role 'Administrator' of "
                        + "user 'jane': the user already has it",
                "Role sync for provider 'keycloak' on the bearer path made no change to the XNAT role 'XnatIQ' of user "
                        + "'jane': the user doesn't have it"), messagesAt(Level.DEBUG, events));
        assertTrue(store.changes.isEmpty());
    }

    @Test
    public void warnsAgainFromAnotherRoleSync() {
        // Each filter builds its own RoleSync, so a once-only warning is once per path, not once per site.
        props.put("roleSync.mappings", "resource_access.xnat:xnat-admin=Administrator");
        final TokenContext token = TokenContext.of(token(clientRoles("xnat", "xnat-admin")));

        final List<ILoggingEvent> events = logDuring(() -> {
            new RoleSync(plugin, store).apply(PROVIDER, AuthPath.BEARER, token, user);
            new RoleSync(plugin, store).apply(PROVIDER, AuthPath.BEARER, token, user);
        });

        assertEquals(2, messagesAt(Level.WARN, events).size());
    }

    @Test
    public void aClaimPathThatStopsAtAnObjectDemotesNobody() {
        store.roles.add("Administrator");
        props.put("roleSync.mappings", "resource_access.xnat:xnat-admin=Administrator");

        sync(AuthPath.BEARER, clientRoles("xnat", "xnat-access", "xnat-admin"));

        assertTrue(store.roles.contains("Administrator"));
    }

    @Test
    public void aClaimHoldingANumberDemotesNobody() {
        store.roles.add("Administrator");
        props.put("roleSync.mappings", "xroles:xnat-admin=Administrator");

        sync(AuthPath.BEARER, Collections.singletonMap("xroles", 42));

        assertTrue(store.roles.contains("Administrator"));
    }

    @Test
    public void readsRolesFromASpaceSeparatedStringClaim() {
        props.put("roleSync.mappings", "xroles:xnat-admin=Administrator");

        sync(AuthPath.BEARER, Collections.singletonMap("xroles", "xnat-access xnat-admin"));

        assertEquals(Collections.singletonList("+Administrator"), store.changes);
    }

    @Test
    public void readsRolesFromAnArrayClaim() {
        props.put("roleSync.mappings", "xroles:xnat-admin=Administrator");

        sync(AuthPath.BEARER, Collections.singletonMap("xroles", new String[] {"xnat-access", "xnat-admin"}));

        assertEquals(Collections.singletonList("+Administrator"), store.changes);
    }

    @Test
    public void readsAClaimWhoseNameHoldsAColon() {
        props.put("roleSync.mappings", "\"cognito:groups\":admins=Administrator");

        sync(AuthPath.BEARER, Collections.singletonMap("cognito:groups", Arrays.asList("admins")));

        assertEquals(Collections.singletonList("+Administrator"), store.changes);
    }

    @Test
    public void readsATokenRoleThatIsADistinguishedName() {
        props.put("roleSync.mappings", "groups:\"cn=admins,ou=groups,dc=example,dc=org\"=Administrator");

        sync(AuthPath.ID_TOKEN, Collections.singletonMap("groups", Arrays.asList("cn=admins,ou=groups,dc=example,dc=org")));

        assertEquals(Collections.singletonList("+Administrator"), store.changes);
    }

    @Test
    public void readsAClaimNamedByAUrl() {
        props.put("roleSync.mappings", "\"https://myapp.example.com/roles\":admin=Administrator");

        sync(AuthPath.ID_TOKEN, Collections.singletonMap("https://myapp.example.com/roles", Arrays.asList("admin")));

        assertEquals(Collections.singletonList("+Administrator"), store.changes);
    }

    @Test
    public void doesNothingWhenEnabledWithoutMappings() {
        store.roles.add("Administrator");
        props.remove("roleSync.mappings");

        final UserI result = sync(AuthPath.BEARER, clientRoles("xnat", "xnat-access"));

        assertSame(user, result);
        assertTrue(store.changes.isEmpty());
    }

    @Test
    public void thePrimaryAdminAndTheReceivedFileUserAreProtectedAccounts() {
        final UserI admin = named("admin");
        final SiteConfigPreferences preferences = mock(SiteConfigPreferences.class);
        when(preferences.getReceivedFileUser()).thenReturn("receiver");
        try (MockedStatic<Users> users = mockStatic(Users.class);
             MockedStatic<XDAT> xdat = mockStatic(XDAT.class)) {
            users.when(Users::getAdminUser).thenReturn(admin);
            xdat.when(XDAT::getSiteConfigPreferences).thenReturn(preferences);
            final RoleSync.RoleStore xnat = new RoleSync.XnatRoleStore();

            assertTrue(xnat.isProtectedAccount(named("admin")));
            assertTrue(xnat.isProtectedAccount(named("receiver")));
            assertFalse(xnat.isProtectedAccount(named("jane")));
        }
    }

    @Test
    public void noAccountIsProtectedWithoutAnAdministratorOrSitePreferences() {
        try (MockedStatic<Users> users = mockStatic(Users.class);
             MockedStatic<XDAT> xdat = mockStatic(XDAT.class)) {
            users.when(Users::getAdminUser).thenReturn(null);
            xdat.when(XDAT::getSiteConfigPreferences).thenReturn(null);

            assertFalse(new RoleSync.XnatRoleStore().isProtectedAccount(named("admin")));
        }
    }

    @Test
    public void theXnatStoreReadsAndChangesRolesAsTheSiteAdministrator() throws Exception {
        final UserI admin = named("admin");
        final UserI jane = named("jane");
        try (MockedStatic<Users> users = mockStatic(Users.class);
             MockedStatic<Roles> roles = mockStatic(Roles.class)) {
            users.when(Users::getAdminUser).thenReturn(admin);
            roles.when(() -> Roles.getRoles(jane)).thenReturn(Collections.singletonList("XnatIQ"));
            roles.when(() -> Roles.addRole(admin, jane, "Administrator")).thenReturn(true);
            roles.when(() -> Roles.deleteRole(admin, jane, "XnatIQ")).thenReturn(true);
            final RoleSync.RoleStore xnat = new RoleSync.XnatRoleStore();

            assertEquals(Collections.singletonList("XnatIQ"), new ArrayList<>(xnat.roles(jane)));
            assertTrue(xnat.add(jane, "Administrator"));
            assertTrue(xnat.remove(jane, "XnatIQ"));
        }
    }

    @Test
    public void theXnatStoreReportsWhenXnatMadeNoChange() throws Exception {
        final UserI admin = named("admin");
        final UserI jane = named("jane");
        try (MockedStatic<Users> users = mockStatic(Users.class);
             MockedStatic<Roles> roles = mockStatic(Roles.class)) {
            users.when(Users::getAdminUser).thenReturn(admin);
            roles.when(() -> Roles.addRole(admin, jane, "Administrator")).thenReturn(false);
            roles.when(() -> Roles.deleteRole(admin, jane, "XnatIQ")).thenReturn(false);
            final RoleSync.RoleStore xnat = new RoleSync.XnatRoleStore();

            assertFalse(xnat.add(jane, "Administrator"));
            assertFalse(xnat.remove(jane, "XnatIQ"));
        }
    }

    @Test
    public void theXnatStoreReadsTheRolesXnatDefines() {
        final RoleDefinitionI administrator = mock(RoleDefinitionI.class);
        when(administrator.getKey()).thenReturn("Administrator");
        final RoleDefinitionI unnamed = mock(RoleDefinitionI.class);
        try (MockedStatic<Roles> roles = mockStatic(Roles.class)) {
            roles.when(Roles::getRoles).thenReturn(Arrays.asList(administrator, unnamed));

            assertEquals(Collections.singleton("Administrator"), new RoleSync.XnatRoleStore().definedRoles());
        }
    }

    @Test
    public void theXnatStoreDefinesNoRolesWhenXnatListsNone() {
        try (MockedStatic<Roles> roles = mockStatic(Roles.class)) {
            roles.when(Roles::getRoles).thenReturn(null);

            assertTrue(new RoleSync.XnatRoleStore().definedRoles().isEmpty());
        }
    }

    @Test
    public void theXnatStoreReloadsNothingWhenTheUserCannotBeLoaded() {
        try (MockedStatic<Users> users = mockStatic(Users.class)) {
            users.when(() -> Users.getUser("jane")).thenThrow(new IllegalStateException("no such user"));

            assertNull(new RoleSync.XnatRoleStore().reload(named("jane")));
        }
    }

    @Test
    public void byDefaultChangesRolesInXnatAndSignsInTheReloadedUser() {
        final UserI admin = named("admin");
        final UserI reloaded = named("jane");
        try (MockedStatic<Users> users = mockStatic(Users.class);
             MockedStatic<Roles> roles = mockStatic(Roles.class)) {
            users.when(Users::getAdminUser).thenReturn(admin);
            users.when(() -> Users.getUser("jane")).thenReturn(reloaded);
            roles.when(() -> Roles.getRoles(user)).thenReturn(Collections.emptyList());
            roles.when(() -> Roles.addRole(admin, user, "Administrator")).thenReturn(true);

            final UserI result = new RoleSync(plugin)
                    .apply(PROVIDER, AuthPath.ID_TOKEN, TokenContext.of(token(clientRoles("xnat", "xnat-admin"))), user);

            assertSame(reloaded, result);
        }
    }

    private UserI sync(final AuthPath path, final Map<String, Object> claims) {
        return new RoleSync(plugin, store).apply(PROVIDER, path, TokenContext.of(token(claims)), user);
    }

    /** The startup report, with the bearer path served for {@code bearerProviders}. */
    private List<ILoggingEvent> report(final String... bearerProviders) {
        return logDuring(() -> new RoleSync(plugin, store).reportSettings(new HashSet<>(Arrays.asList(bearerProviders))));
    }

    /** The provider's settings as the plugin holds them, plus any written outside its namespace. */
    private Properties settings() {
        final Properties settings = new Properties();
        props.forEach((name, value) -> settings.setProperty("openid." + PROVIDER + "." + name, value));
        settings.putAll(otherSettings);
        return settings;
    }

    private static List<String> messagesAt(final Level level, final List<ILoggingEvent> events) {
        final List<String> messages = new ArrayList<>();
        for (final ILoggingEvent event : events) {
            if (event.getLevel().equals(level)) {
                messages.add(event.getFormattedMessage());
            }
        }
        return messages;
    }

    private static List<ILoggingEvent> warningsDuring(final Runnable action) {
        final List<ILoggingEvent> warnings = new ArrayList<>();
        for (final ILoggingEvent event : logDuring(action)) {
            if (event.getLevel().isGreaterOrEqual(Level.WARN)) {
                warnings.add(event);
            }
        }
        return warnings;
    }

    private static List<ILoggingEvent> logDuring(final Runnable action) {
        final Logger logger = (Logger) LoggerFactory.getLogger(RoleSync.class);
        final ListAppender<ILoggingEvent> appender = new ListAppender<>();
        appender.start();
        logger.addAppender(appender);
        try {
            action.run();
        } finally {
            logger.detachAppender(appender);
        }
        return appender.list;
    }

    private static Map<String, Object> clientRoles(final String client, final String... roles) {
        final Map<String, Object> claims = new HashMap<>();
        final Map<String, Object> access = new HashMap<>();
        access.put(client, Collections.singletonMap("roles", Arrays.asList(roles)));
        claims.put("resource_access", access);
        return claims;
    }

    private static JWTClaimsSet token(final Map<String, Object> claims) {
        final JWTClaimsSet.Builder builder = new JWTClaimsSet.Builder().subject("jane");
        claims.forEach(builder::claim);
        return builder.build();
    }

    private static UserI named(final String username) {
        final UserI named = mock(UserI.class);
        lenient().when(named.getUsername()).thenReturn(username);
        return named;
    }

    private static final class FakeStore implements RoleSync.RoleStore {
        final Set<String> roles = new LinkedHashSet<>();
        final List<String> changes = new ArrayList<>();
        final UserI reloaded = mock(UserI.class);
        boolean failAdd;
        boolean failRemove;
        boolean noChange;
        boolean reloadFails;
        boolean protectedAccount;
        boolean protectedAccountFails;
        boolean rolesFail;
        boolean definedFails;
        final Set<String> defined = new LinkedHashSet<>(Arrays.asList("Administrator", "XnatIQ", "Data Manager", "Legacy"));

        @Override
        public Collection<String> roles(final UserI user) {
            if (rolesFail) {
                throw new IllegalStateException("database down");
            }
            return new ArrayList<>(roles);
        }

        @Override
        public Set<String> definedRoles() {
            if (definedFails) {
                throw new IllegalStateException("no role service");
            }
            return defined;
        }

        @Override
        public boolean add(final UserI user, final String role) throws Exception {
            if (failAdd) {
                throw new Exception("refused");
            }
            if (noChange) {
                return false;
            }
            roles.add(role);
            changes.add("+" + role);
            return true;
        }

        @Override
        public boolean remove(final UserI user, final String role) throws Exception {
            if (failRemove) {
                throw new Exception("refused");
            }
            if (noChange) {
                return false;
            }
            roles.remove(role);
            changes.add("-" + role);
            return true;
        }

        @Override
        public UserI reload(final UserI user) {
            return reloadFails ? null : reloaded;
        }

        @Override
        public boolean isProtectedAccount(final UserI user) {
            if (protectedAccountFails) {
                throw new IllegalStateException("the primary administrator could not be loaded");
            }
            return protectedAccount;
        }
    }
}

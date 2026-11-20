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
import org.mockito.junit.MockitoJUnitRunner;
import org.nrg.xft.security.UserI;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertTrue;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;

@RunWith(MockitoJUnitRunner.class)
public class RoleSyncTest {

    private static final String PROVIDER = "keycloak";
    private static final String MAPPINGS =
            "resource_access.xnat.roles:xnat-admin=Administrator, resource_access.datasets.roles:datasets-iq-admin=XnatIQ";

    @Mock private OpenIdAuthPlugin plugin;

    private final Map<String, String> props = new HashMap<>();
    private final FakeStore store = new FakeStore();
    private final UserI user = mock(UserI.class);

    @Before
    public void setUp() {
        lenient().when(plugin.getProperty(eq(PROVIDER), anyString()))
                .thenAnswer(invocation -> props.get(invocation.getArgument(1)));
        lenient().when(user.getUsername()).thenReturn("jane");
        props.put("roleSync.enabled", "true");
        props.put("roleSync.mappings", MAPPINGS);
    }

    private UserI sync(final AuthPath path, final Map<String, Object> claims) {
        return new RoleSync(plugin, store).apply(PROVIDER, path, TokenContext.of(token(claims)), user);
    }

    @Test
    public void grantsMappedRoleWhenTokenCarriesIt() {
        final UserI result = sync(AuthPath.ID_TOKEN, clientRoles("xnat", "xnat-access", "xnat-admin"));

        assertEquals(Collections.singletonList("+Administrator"), store.changes);
        assertSame(store.reloaded, result);
    }

    @Test
    public void removesMappedRoleWhenClaimPathPresentWithoutTheRole() {
        store.roles.add("Administrator");

        sync(AuthPath.ID_TOKEN, clientRoles("xnat", "xnat-access"));

        assertEquals(Collections.singletonList("-Administrator"), store.changes);
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
    public void failedChangeGrantsNothingAndKeepsUser() {
        store.failAdd = true;

        final UserI result = sync(AuthPath.ID_TOKEN, clientRoles("xnat", "xnat-admin"));

        assertTrue(store.changes.isEmpty());
        assertSame(user, result);
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
    public void neverRemovesARoleFromThePrimaryAdmin() {
        store.roles.add("Administrator");
        store.primaryAdmin = true;

        final UserI result = sync(AuthPath.ID_TOKEN, clientRoles("xnat", "xnat-access"));

        assertTrue(store.changes.isEmpty());
        assertSame(user, result);
    }

    @Test
    public void stillAddsRolesToThePrimaryAdmin() {
        store.primaryAdmin = true;

        sync(AuthPath.BEARER, clientRoles("datasets", "datasets-iq-admin"));

        assertEquals(Collections.singletonList("+XnatIQ"), store.changes);
    }

    @Test
    public void appliesTheRestWithoutAWarningWhenAnEntryIsMalformed() {
        props.put("roleSync.mappings", "nocolon=Role, " + MAPPINGS);
        final Logger logger = (Logger) LoggerFactory.getLogger(RoleSync.class);
        final ListAppender<ILoggingEvent> appender = new ListAppender<>();
        appender.start();
        logger.addAppender(appender);
        try {
            sync(AuthPath.BEARER, clientRoles("xnat", "xnat-access", "xnat-admin"));
        } finally {
            logger.detachAppender(appender);
        }

        assertEquals(Collections.singletonList("+Administrator"), store.changes);
        assertTrue("a malformed entry is reported at startup, not at each sign-in",
                appender.list.stream().noneMatch(event -> event.getLevel().isGreaterOrEqual(Level.WARN)));
    }

    @Test
    public void listsEachMalformedMappingOnceAcrossPaths() {
        props.put("roleSync.mappings", "nocolon=Role, " + MAPPINGS);
        props.put("idToken.roleSync.mappings", "nocolon=Role, path:role=, groups:xnat-admin=Administrator");

        assertEquals(new LinkedHashSet<>(Arrays.asList("nocolon=Role", "path:role=")),
                new RoleSync(plugin, store).malformedMappings(PROVIDER));
    }

    @Test
    public void listsNoMalformedMappingsWhenRoleSyncIsOff() {
        props.remove("roleSync.enabled");
        props.put("roleSync.mappings", "nocolon=Role");

        assertTrue(new RoleSync(plugin, store).malformedMappings(PROVIDER).isEmpty());
    }

    @Test
    public void parseSkipsMalformedEntries() {
        final List<RoleSync.Mapping> mappings = RoleSync.parse(
                "resource_access.xnat.roles:xnat-admin=Administrator, nocolon=Role, path:role=, :role=Role, path:=Role");

        assertEquals(1, mappings.size());
        assertEquals("xnat-admin", mappings.get(0).tokenRole);
        assertEquals("Administrator", mappings.get(0).xnatRole);
        assertEquals(Arrays.asList("resource_access", "xnat", "roles"), Arrays.asList(mappings.get(0).path));
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

    private static final class FakeStore implements RoleSync.RoleStore {
        final Set<String> roles = new LinkedHashSet<>();
        final List<String> changes = new ArrayList<>();
        final UserI reloaded = mock(UserI.class);
        boolean failAdd;
        boolean primaryAdmin;

        @Override
        public Collection<String> roles(final UserI user) {
            return new ArrayList<>(roles);
        }

        @Override
        public void add(final UserI user, final String role) throws Exception {
            if (failAdd) {
                throw new Exception("refused");
            }
            roles.add(role);
            changes.add("+" + role);
        }

        @Override
        public void remove(final UserI user, final String role) {
            roles.remove(role);
            changes.add("-" + role);
        }

        @Override
        public UserI reload(final UserI user) {
            return reloaded;
        }

        @Override
        public boolean isPrimaryAdmin(final UserI user) {
            return primaryAdmin;
        }
    }
}

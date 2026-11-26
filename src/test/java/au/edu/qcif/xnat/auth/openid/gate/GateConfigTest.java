package au.edu.qcif.xnat.auth.openid.gate;

import au.edu.qcif.xnat.auth.openid.OpenIdAuthPlugin;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;

import java.util.HashMap;
import java.util.Map;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.lenient;

/**
 * Unit tests for {@link GateConfig}: a path-scoped setting ({@code openid.{p}.{path}.{field}}) replaces the
 * shared one ({@code openid.{p}.{field}}) when it is set, and a blank one falls back to the shared one.
 */
@RunWith(MockitoJUnitRunner.class)
public class GateConfigTest {

    private static final String PROVIDER = "keycloak";

    @Mock private OpenIdAuthPlugin plugin;

    private final Map<String, String> props = new HashMap<>();

    @Before
    public void setUp() {
        lenient().when(plugin.getProperty(eq(PROVIDER), anyString()))
                 .thenAnswer(invocation -> props.get(invocation.getArgument(1)));
    }

    private GateConfig on(final AuthPath path) {
        return new GateConfig(plugin, PROVIDER, path);
    }

    @Test
    public void readsThePathScopedValueWhenItIsSet() {
        props.put("roleSync.mappings", "shared");
        props.put("idToken.roleSync.mappings", "browser only");

        assertEquals("browser only", on(AuthPath.ID_TOKEN).value("roleSync.mappings"));
    }

    @Test
    public void readsTheSharedValueWhenThePathHasNone() {
        props.put("roleSync.mappings", "shared");

        assertEquals("shared", on(AuthPath.BEARER).value("roleSync.mappings"));
    }

    @Test
    public void readsTheSharedValueWhenThePathScopedOneIsBlank() {
        props.put("roleSync.mappings", "shared");
        props.put("bearer.roleSync.mappings", "  ");

        assertEquals("shared", on(AuthPath.BEARER).value("roleSync.mappings"));
    }

    @Test
    public void readsNothingWhenNeitherIsSet() {
        assertNull(on(AuthPath.ID_TOKEN).value("roleSync.mappings"));
    }

    @Test
    public void namesThePathScopedSettingWhenItIsSet() {
        props.put("roleSync.mappings", "shared");
        props.put("idToken.roleSync.mappings", "browser only");

        assertEquals("openid.keycloak.idToken.roleSync.mappings", on(AuthPath.ID_TOKEN).key("roleSync.mappings"));
    }

    @Test
    public void namesTheSharedSettingWhenThePathHasNone() {
        props.put("roleSync.mappings", "shared");

        assertEquals("openid.keycloak.roleSync.mappings", on(AuthPath.BEARER).key("roleSync.mappings"));
    }

    @Test
    public void namesTheSharedSettingWhenThePathScopedOneIsBlank() {
        props.put("bearer.roleSync.mappings", "");

        assertEquals("openid.keycloak.roleSync.mappings", on(AuthPath.BEARER).key("roleSync.mappings"));
    }

    @Test
    public void isEnabledWhenThePathScopedToggleIsTrue() {
        props.put("roleSync.enabled", "false");
        props.put("idToken.roleSync.enabled", "true");

        assertTrue(on(AuthPath.ID_TOKEN).enabled("roleSync"));
    }

    @Test
    public void isDisabledWhenThePathScopedToggleIsFalseOverASharedTrue() {
        props.put("roleSync.enabled", "true");
        props.put("bearer.roleSync.enabled", "false");

        assertFalse(on(AuthPath.BEARER).enabled("roleSync"));
    }

    @Test
    public void isDisabledByDefault() {
        assertFalse(on(AuthPath.ID_TOKEN).enabled("roleSync"));
        assertFalse(on(AuthPath.BEARER).enabled("roleSync"));
    }

    @Test
    public void checksTheAudienceOfBearerTokensByDefaultOnly() {
        assertTrue(on(AuthPath.BEARER).enabled("audCheck"));
        assertFalse(on(AuthPath.ID_TOKEN).enabled("audCheck"));
    }

    @Test
    public void letsAnExplicitSettingTurnOffTheBearerAudienceCheck() {
        props.put("bearer.audCheck.enabled", "false");

        assertFalse(on(AuthPath.BEARER).enabled("audCheck"));
    }
}

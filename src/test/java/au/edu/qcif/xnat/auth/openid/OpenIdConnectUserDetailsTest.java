package au.edu.qcif.xnat.auth.openid;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;

import java.util.HashMap;
import java.util.Map;

import static au.edu.qcif.xnat.auth.openid.etc.OpenIdAuthConstant.*;
import static org.junit.Assert.*;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link OpenIdConnectUserDetails}, focused on username-pattern resolution and the
 * mapping of OIDC claims onto user fields. No live identity provider or XNAT context is needed: the
 * only collaborator, {@link OpenIdAuthPlugin}, is mocked and the claim set is supplied directly as a map.
 */
@RunWith(MockitoJUnitRunner.class)
public class OpenIdConnectUserDetailsTest {

    private static final String PROVIDER = "keycloak";

    @Mock
    private OpenIdAuthPlugin plugin;

    private Map<String, String> userInfo;

    @Before
    public void setUp() {
        userInfo = new HashMap<>();
        userInfo.put("sub", "12345");
    }

    /** Tells the mock plugin which claim key backs a given configurable property. */
    private void mapProperty(final String propName, final String value) {
        lenient().when(plugin.getProperty(PROVIDER, propName)).thenReturn(value);
    }

    private OpenIdConnectUserDetails build() {
        return new OpenIdConnectUserDetails(PROVIDER, userInfo, null, plugin);
    }

    @Test
    public void defaultUsernamePatternCombinesProviderIdAndSub() {
        // No usernamePattern configured -> falls back to "[providerId]_[sub]".
        final OpenIdConnectUserDetails details = build();

        assertEquals("keycloak_12345", details.getUsername());
    }

    @Test
    public void customUsernamePatternResolvesMultipleClaims() {
        mapProperty(USERNAME_PATTERN, "[preferred_username]@[domain]");
        userInfo.put("preferred_username", "jdoe");
        userInfo.put("domain", "example.org");

        assertEquals("jdoe@example.org", build().getUsername());
    }

    @Test
    public void missingClaimInUsernamePatternThrows() {
        mapProperty(USERNAME_PATTERN, "[providerId]_[employeeId]");
        // "employeeId" is not present in userInfo.

        try {
            build();
            fail("Expected IllegalArgumentException when a username-pattern claim is missing");
        } catch (IllegalArgumentException expected) {
            assertTrue("Message should name the missing claim",
                       expected.getMessage().contains("employeeId"));
        }
    }

    @Test
    public void mapsConfiguredEmailAndNameClaims() {
        mapProperty(EMAIL, "email");
        mapProperty(GIVEN_NAME, "given_name");
        mapProperty(FAMILY_NAME, "family_name");
        userInfo.put("email", "jane.doe@example.org");
        userInfo.put("given_name", "Jane");
        userInfo.put("family_name", "Doe");

        final OpenIdConnectUserDetails details = build();

        assertEquals("jane.doe@example.org", details.getEmail());
        assertEquals("Jane", details.getFirstname());
        assertEquals("Doe", details.getLastname());
    }

    @Test
    public void absentNameClaimsResolveToEmptyString() {
        mapProperty(EMAIL, "email");
        mapProperty(GIVEN_NAME, "given_name");
        // family_name property is configured but the claim is absent from the response.
        mapProperty(FAMILY_NAME, "family_name");
        userInfo.put("email", "jane.doe@example.org");
        userInfo.put("given_name", "Jane");

        final OpenIdConnectUserDetails details = build();

        assertEquals("", details.getLastname());
    }

    @Test
    public void getFieldValueReadsDeclaredFieldThenFallsBackToClaims() {
        final OpenIdConnectUserDetails details = build();

        // Declared field on the class, resolved via reflection.
        assertEquals("keycloak", details.getFieldValue("providerId"));
        // Not a declared field -> falls back to the claims map.
        assertEquals("12345", details.getFieldValue("sub"));
        // Neither a field nor a claim -> null.
        assertNull(details.getFieldValue("does_not_exist"));
    }
}

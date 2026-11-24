package au.edu.qcif.xnat.auth.openid.discovery;

import au.edu.qcif.xnat.auth.openid.OpenIdAuthPlugin;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;
import org.springframework.mock.web.MockHttpServletRequest;

import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;
import java.util.Properties;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.lenient;

@RunWith(MockitoJUnitRunner.class)
public class ProtectedResourceMetadataTest {

    private static final String PROVIDER = "keycloak";
    private static final String ISSUER = "https://keycloak.example/realms/scout";

    @Mock private OpenIdAuthPlugin plugin;

    private final Properties props = new Properties();

    @Before
    public void setUp() {
        lenient().when(plugin.getProps()).thenReturn(props);
        lenient().when(plugin.getProperty(anyString()))
                .thenAnswer(call -> props.getProperty("openid." + call.getArgument(0)));
        lenient().when(plugin.getProperty(anyString(), anyString()))
                .thenAnswer(call -> props.getProperty("openid." + call.getArgument(0) + "." + call.getArgument(1)));
        lenient().when(plugin.isEnabled(PROVIDER)).thenReturn(true);
        lenient().when(plugin.getSiteUrl()).thenReturn("https://xnat.example/");
        props.setProperty("openid.keycloak.bearer.enabled", "true");
        props.setProperty("openid.keycloak.issuer", ISSUER);
        props.setProperty("openid.keycloak.jwksUri", ISSUER + "/protocol/openid-connect/certs");
        props.setProperty("openid.discovery.enabled", "true");
        props.setProperty("openid.discovery.provider", PROVIDER);
    }

    private static MockHttpServletRequest request(final String host, final String contextPath) {
        final MockHttpServletRequest request = new MockHttpServletRequest("GET", contextPath + "/.well-known/oauth-protected-resource");
        request.setServerName(host);
        request.setContextPath(contextPath);
        return request;
    }

    @Test
    public void isDisabledUnlessSwitchedOn() {
        props.remove("openid.discovery.enabled");

        final ProtectedResourceMetadata metadata = new ProtectedResourceMetadata(plugin);

        assertFalse(metadata.isEnabled());
        assertEquals(Optional.empty(), metadata.resourceFor(request("xnat.example", ""), ""));
        assertEquals(Optional.empty(), metadata.metadataUrlFor(request("xnat.example", "")));
    }

    @Test
    public void isDisabledWithoutAProvider() {
        props.remove("openid.discovery.provider");

        assertFalse(new ProtectedResourceMetadata(plugin).isEnabled());
    }

    @Test
    public void isDisabledWhenTheProviderDoesNotAcceptBearerTokens() {
        props.setProperty("openid.keycloak.bearer.enabled", "false");

        assertFalse(new ProtectedResourceMetadata(plugin).isEnabled());
    }

    @Test
    public void isDisabledWhenTheProviderHasNoJwksUri() {
        props.remove("openid.keycloak.jwksUri");

        assertFalse(new ProtectedResourceMetadata(plugin).isEnabled());
    }

    @Test
    public void isDisabledWhenTheProviderIsNotEnabled() {
        lenient().when(plugin.isEnabled(PROVIDER)).thenReturn(false);

        assertFalse(new ProtectedResourceMetadata(plugin).isEnabled());
    }

    @Test
    public void documentCarriesEveryConfiguredField() {
        props.setProperty("openid.discovery.resourceName", "Example XNAT");
        props.setProperty("openid.discovery.scopes", "openid, profile");
        props.setProperty("openid.discovery.documentation", "https://xnat.example/xapi/swagger-ui.html");
        props.setProperty("openid.discovery.apiUrl", "https://xnat-api.example/");
        props.setProperty("openid.discovery.webUrl", "https://xnat.example");
        props.setProperty("openid.discovery.clients.xnat-workstation.clientId", "xnat-workstation");
        props.setProperty("openid.discovery.clients.xnatpy.clientId", "xnatpy");
        props.setProperty("openid.discovery.clients.xnatpy.scope", "openid offline_access");
        props.setProperty("openid.discovery.clients.default.clientId", "xnat-tools");
        props.setProperty("openid.discovery.clients.orphan.scope", "openid");

        final Map<String, Object> expected = new LinkedHashMap<>();
        expected.put("resource", "https://xnat.example");
        expected.put("resource_name", "Example XNAT");
        expected.put("authorization_servers", Collections.singletonList(ISSUER));
        expected.put("scopes_supported", Arrays.asList("openid", "profile"));
        expected.put("bearer_methods_supported", Collections.singletonList("header"));
        expected.put("resource_documentation", "https://xnat.example/xapi/swagger-ui.html");
        expected.put("xnat_api_url", "https://xnat-api.example");
        expected.put("xnat_web_url", "https://xnat.example");
        final Map<String, Object> clients = new LinkedHashMap<>();
        clients.put("default", client("xnat-tools", "openid profile"));
        clients.put("xnat-workstation", client("xnat-workstation", "openid profile"));
        clients.put("xnatpy", client("xnatpy", "openid offline_access"));
        expected.put("xnat_clients", clients);

        final Map<String, Object> document = new ProtectedResourceMetadata(plugin).document("https://xnat.example");

        assertEquals(expected, document);
        assertEquals(Arrays.asList(expected.keySet().toArray()), Arrays.asList(document.keySet().toArray()));
    }

    @Test
    public void documentDefaultsUrlsToTheSiteUrlAndScopeToOpenid() {
        final Map<String, Object> document = new ProtectedResourceMetadata(plugin).document("https://xnat.example");

        assertEquals(Collections.singletonList("openid"), document.get("scopes_supported"));
        assertEquals("https://xnat.example", document.get("xnat_api_url"));
        assertEquals("https://xnat.example", document.get("xnat_web_url"));
        assertEquals(Collections.emptyMap(), document.get("xnat_clients"));
        assertFalse(document.containsKey("resource_name"));
        assertFalse(document.containsKey("resource_documentation"));
    }

    @Test
    public void resourceIsTheConfiguredUrlForTheRequestHost() {
        props.setProperty("openid.discovery.apiUrl", "https://xnat-api.example");
        final ProtectedResourceMetadata metadata = new ProtectedResourceMetadata(plugin);

        assertEquals(Optional.of("https://xnat.example"), metadata.resourceFor(request("XNAT.example", ""), ""));
        assertEquals(Optional.of("https://xnat-api.example"), metadata.resourceFor(request("xnat-api.example", ""), ""));
    }

    @Test
    public void unconfiguredHostGetsNoResource() {
        assertEquals(Optional.empty(), new ProtectedResourceMetadata(plugin).resourceFor(request("attacker.example", ""), ""));
    }

    @Test
    public void suffixMustBeTheResourcePath() {
        assertEquals(Optional.empty(), new ProtectedResourceMetadata(plugin).resourceFor(request("xnat.example", ""), "/other"));
    }

    @Test
    public void contextPathResourceMatchesEitherForm() {
        lenient().when(plugin.getSiteUrl()).thenReturn("https://xnat.example/xnat");
        final ProtectedResourceMetadata metadata = new ProtectedResourceMetadata(plugin);

        // RFC 9728 form, routed into the webapp: /xnat/.well-known/oauth-protected-resource/xnat
        assertEquals(Optional.of("https://xnat.example/xnat"), metadata.resourceFor(request("xnat.example", "/xnat"), "/xnat"));
        // Inside the context path: /xnat/.well-known/oauth-protected-resource
        assertEquals(Optional.of("https://xnat.example/xnat"), metadata.resourceFor(request("xnat.example", "/xnat"), ""));
        // At the host root, without the resource path
        assertEquals(Optional.empty(), metadata.resourceFor(request("xnat.example", ""), ""));
    }

    @Test
    public void metadataUrlUsesTheRfc9728Location() {
        assertEquals(Optional.of("https://xnat.example/.well-known/oauth-protected-resource"),
                new ProtectedResourceMetadata(plugin).metadataUrlFor(request("xnat.example", "")));

        lenient().when(plugin.getSiteUrl()).thenReturn("https://xnat.example/xnat");
        assertEquals(Optional.of("https://xnat.example/.well-known/oauth-protected-resource/xnat"),
                new ProtectedResourceMetadata(plugin).metadataUrlFor(request("xnat.example", "/xnat")));
    }

    private static Map<String, String> client(final String clientId, final String scope) {
        final Map<String, String> client = new LinkedHashMap<>();
        client.put("client_id", clientId);
        client.put("scope", scope);
        return client;
    }
}

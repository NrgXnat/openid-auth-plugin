package au.edu.qcif.xnat.auth.openid.discovery;

import au.edu.qcif.xnat.auth.openid.OpenIdAuthPlugin;
import com.nimbusds.jose.util.JSONObjectUtils;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import java.util.Collections;
import java.util.Map;
import java.util.Properties;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertSame;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.lenient;

@RunWith(MockitoJUnitRunner.class)
public class ProtectedResourceMetadataFilterTest {

    private static final String ISSUER = "https://keycloak.example/realms/scout";

    @Mock private OpenIdAuthPlugin plugin;

    private final Properties props = new Properties();
    private MockHttpServletResponse response;
    private MockFilterChain chain;

    @Before
    public void setUp() {
        lenient().when(plugin.getProps()).thenReturn(props);
        lenient().when(plugin.getProperty(anyString()))
                .thenAnswer(call -> props.getProperty("openid." + call.getArgument(0)));
        lenient().when(plugin.getProperty(anyString(), anyString()))
                .thenAnswer(call -> props.getProperty("openid." + call.getArgument(0) + "." + call.getArgument(1)));
        lenient().when(plugin.isEnabled("keycloak")).thenReturn(true);
        lenient().when(plugin.getSiteUrl()).thenReturn("https://xnat.example");
        props.setProperty("openid.keycloak.bearer.enabled", "true");
        props.setProperty("openid.keycloak.issuer", ISSUER);
        props.setProperty("openid.keycloak.jwksUri", ISSUER + "/protocol/openid-connect/certs");
        props.setProperty("openid.discovery.enabled", "true");
        props.setProperty("openid.discovery.provider", "keycloak");
        props.setProperty("openid.discovery.clients.default.clientId", "xnat-tools");
        response = new MockHttpServletResponse();
        chain = new MockFilterChain();
    }

    private void filter(final MockHttpServletRequest request) throws Exception {
        new ProtectedResourceMetadataFilter(new ProtectedResourceMetadata(plugin)).doFilter(request, response, chain);
    }

    private static MockHttpServletRequest request(final String method, final String contextPath, final String path) {
        final MockHttpServletRequest request = new MockHttpServletRequest(method, contextPath + path);
        request.setServerName("xnat.example");
        request.setContextPath(contextPath);
        return request;
    }

    @Test
    public void anonymousGetIsAnsweredWithoutASession() throws Exception {
        final MockHttpServletRequest request = request("GET", "", "/.well-known/oauth-protected-resource");

        filter(request);

        assertEquals(200, response.getStatus());
        assertEquals("application/json;charset=UTF-8", response.getContentType());
        assertEquals(ProtectedResourceMetadataFilter.CACHE_CONTROL, response.getHeader("Cache-Control"));
        assertNull("the chain, and so the login redirect, must not run", chain.getRequest());
        assertNull("no session may be created", request.getSession(false));
        assertNull(response.getCookie("JSESSIONID"));
        final Map<String, Object> body = JSONObjectUtils.parse(response.getContentAsString());
        assertEquals("https://xnat.example", body.get("resource"));
        assertEquals(Collections.singletonList(ISSUER), body.get("authorization_servers"));
        assertEquals(Collections.singletonList("header"), body.get("bearer_methods_supported"));
        assertNotNull(((Map<?, ?>) body.get("xnat_clients")).get("default"));
    }

    @Test
    public void headGetsTheHeadersWithoutABody() throws Exception {
        filter(request("HEAD", "", "/.well-known/oauth-protected-resource"));

        assertEquals(200, response.getStatus());
        assertEquals("application/json;charset=UTF-8", response.getContentType());
        assertEquals("", response.getContentAsString());
        assertNull(chain.getRequest());
    }

    @Test
    public void rfc9728SuffixFormIsAnsweredUnderAContextPath() throws Exception {
        lenient().when(plugin.getSiteUrl()).thenReturn("https://xnat.example/xnat");

        filter(request("GET", "/xnat", "/.well-known/oauth-protected-resource/xnat"));

        assertEquals(200, response.getStatus());
        assertEquals("https://xnat.example/xnat", JSONObjectUtils.parse(response.getContentAsString()).get("resource"));
    }

    @Test
    public void disabledDiscoveryFallsThrough() throws Exception {
        props.remove("openid.discovery.enabled");
        final MockHttpServletRequest request = request("GET", "", "/.well-known/oauth-protected-resource");

        filter(request);

        assertSame(request, chain.getRequest());
        assertEquals("", response.getContentAsString());
    }

    @Test
    public void unconfiguredHostFallsThrough() throws Exception {
        final MockHttpServletRequest request = request("GET", "", "/.well-known/oauth-protected-resource");
        request.setServerName("attacker.example");

        filter(request);

        assertSame(request, chain.getRequest());
    }

    @Test
    public void otherMethodsFallThrough() throws Exception {
        final MockHttpServletRequest request = request("POST", "", "/.well-known/oauth-protected-resource");

        filter(request);

        assertSame(request, chain.getRequest());
    }

    @Test
    public void otherPathsFallThrough() throws Exception {
        final MockHttpServletRequest request = request("GET", "", "/.well-known/oauth-protected-resourcex");

        filter(request);

        assertSame(request, chain.getRequest());
    }
}

package au.edu.qcif.xnat.auth.openid;

import au.edu.qcif.xnat.auth.openid.etc.OpenIdAuthConstant;
import au.edu.qcif.xnat.auth.openid.security.ProviderSessionFilter;
import au.edu.qcif.xnat.auth.openid.tokens.OpenIdAuthToken;
import com.github.tomakehurst.wiremock.junit.WireMockRule;
import org.apache.commons.io.IOUtils;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.nrg.framework.services.SerializerService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.ClassPathResource;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.jwt.JwtHelper;
import org.springframework.security.jwt.crypto.sign.MacSigner;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import static au.edu.qcif.xnat.auth.openid.OpenIdConnectFilterTestConfig.TEST_ACCESS_TOKEN;
import static au.edu.qcif.xnat.auth.openid.OpenIdConnectFilterTestConfig.TEST_PROVIDER_ID;
import static au.edu.qcif.xnat.auth.openid.etc.OpenIdAuthConstant.ACCESS_TOKEN;
import static au.edu.qcif.xnat.auth.openid.etc.OpenIdAuthConstant.ID_TOKEN;
import static com.github.tomakehurst.wiremock.client.WireMock.*;
import static java.nio.charset.Charset.defaultCharset;
import static org.junit.Assert.*;

@SuppressWarnings("deprecation")
@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration(classes = OpenIdConnectFilterTestConfig.class)
public class OpenIdConnectFilterTest {

    @Rule
    public final WireMockRule wireMockRule = new WireMockRule(8081);

    private OpenIdConnectFilter filter;
    private SerializerService   serializer;

    public OpenIdConnectFilterTest() {
        System.setProperty("xnat.home", System.getProperty("user.dir"));
    }

    @Autowired
    public void setOpenIdConnectFilter(final OpenIdConnectFilter openIdConnectFilter) {
        filter = openIdConnectFilter;
    }

    @Autowired
    public void setSerializerService(final SerializerService serializerService) {
        serializer = serializerService;
    }

    @Test
    public void attemptAuthentication() throws Exception {
        stubFor(post(urlEqualTo("/auth")).willReturn(aResponse().withStatus(302).withHeader(HttpHeaders.LOCATION, "http://localhost:8081?code=code")));

        final Map<String, Object> body = new HashMap<>();
        body.put(ACCESS_TOKEN, TEST_ACCESS_TOKEN);
        body.put(ID_TOKEN, JwtHelper.encode(readFile("id_token.json"), new MacSigner("secret")).getEncoded());
        body.put("refresh_token", "test-refresh-token");
        body.put("expires_in", 300);
        final String json = serializer.toJson(body);

        stubFor(post(urlEqualTo("/token")).willReturn(aResponse()
                                                              .withStatus(200)
                                                              .withHeader(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE)
                                                              .withBody(json)));
        stubFor(get(urlEqualTo("/userinfo")).willReturn(aResponse()
                                                                .withStatus(200)
                                                                .withHeader(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE)
                                                                .withBody(readFile("user_info.json"))));

        final HttpServletRequest  request  = new MockHttpServletRequest();
        final HttpServletResponse response = new MockHttpServletResponse();

        request.getSession().setAttribute(OpenIdAuthConstant.PROVIDER_ID, TEST_PROVIDER_ID);

        final Authentication authentication = filter.attemptAuthentication(request, response);

        assertNotNull(authentication);
        assertTrue(authentication instanceof OpenIdAuthToken);
        final OpenIdAuthToken token = (OpenIdAuthToken) authentication;
        assertEquals(token.getProviderId(), TEST_PROVIDER_ID);
        // The test provider sets followProviderSession, so sign-in keeps what the session check needs.
        assertEquals("test-refresh-token", request.getSession().getAttribute(ProviderSessionFilter.REFRESH_TOKEN_ATTR));
        assertNotNull(request.getSession().getAttribute(ProviderSessionFilter.CHECK_AT_ATTR));
    }

    private String readFile(String fileName) throws IOException {
        return IOUtils.toString(new ClassPathResource(fileName).getInputStream(), defaultCharset());
    }
}

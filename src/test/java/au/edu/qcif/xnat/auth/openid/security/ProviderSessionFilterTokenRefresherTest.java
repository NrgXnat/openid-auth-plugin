package au.edu.qcif.xnat.auth.openid.security;

import com.github.tomakehurst.wiremock.junit.WireMockRule;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.security.oauth2.client.resource.OAuth2AccessDeniedException;
import org.springframework.security.oauth2.client.token.grant.code.AuthorizationCodeResourceDetails;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.exceptions.InvalidGrantException;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.containing;
import static com.github.tomakehurst.wiremock.client.WireMock.matching;
import static com.github.tomakehurst.wiremock.client.WireMock.post;
import static com.github.tomakehurst.wiremock.client.WireMock.postRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.stubFor;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static com.github.tomakehurst.wiremock.client.WireMock.verify;
import static com.github.tomakehurst.wiremock.core.WireMockConfiguration.wireMockConfig;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

/**
 * Runs the refresh request against a real HTTP token endpoint, since what the filter acts on is how the OAuth2
 * library reports each kind of failure.
 */
public class ProviderSessionFilterTokenRefresherTest {

    @Rule
    public final WireMockRule wireMockRule = new WireMockRule(wireMockConfig().dynamicPort());

    private final ProviderSessionFilter.TokenRefresher refresher = new ProviderSessionFilter.TokenRefresher();
    private final AuthorizationCodeResourceDetails     resource  = new AuthorizationCodeResourceDetails();

    @Before
    public void setUp() {
        resource.setClientId("xnat");
        resource.setClientSecret("secret");
        resource.setAccessTokenUri("http://localhost:" + wireMockRule.port() + "/token");
    }

    private static void tokenEndpointReturns(final int status, final String json) {
        stubFor(post(urlEqualTo("/token")).willReturn(aResponse()
                                                              .withStatus(status)
                                                              .withHeader(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE)
                                                              .withBody(json)));
    }

    private OAuth2AccessDeniedException refreshFails() {
        try {
            refresher.refresh(resource, "rt-1");
        } catch (final OAuth2AccessDeniedException e) {
            return e;
        }
        fail("the refresh should have failed");
        return null;
    }

    @Test
    public void successfulRefreshReturnsTheNewTokens() {
        tokenEndpointReturns(200, "{\"access_token\":\"at-2\",\"token_type\":\"Bearer\",\"expires_in\":300,\"refresh_token\":\"rt-2\"}");

        final OAuth2AccessToken token = refresher.refresh(resource, "rt-1");

        assertEquals("rt-2", token.getRefreshToken().getValue());
        assertNotNull(token.getExpiration());
        verify(postRequestedFor(urlEqualTo("/token"))
                       .withRequestBody(containing("grant_type=refresh_token"))
                       .withRequestBody(containing("refresh_token=rt-1"))
                       .withHeader(HttpHeaders.AUTHORIZATION, matching("Basic .+")));
    }

    @Test
    public void rejectedRefreshTokenSurfacesAsInvalidGrant() {
        // What Keycloak returns once the session behind the refresh token has ended.
        tokenEndpointReturns(400, "{\"error\":\"invalid_grant\",\"error_description\":\"Session not active\"}");

        assertTrue(refreshFails().getCause() instanceof InvalidGrantException);
    }

    @Test
    public void rejectedClientIsNotInvalidGrant() {
        tokenEndpointReturns(401, "{\"error\":\"unauthorized_client\",\"error_description\":\"Invalid client secret\"}");

        assertFalse(refreshFails().getCause() instanceof InvalidGrantException);
    }

    @Test
    public void providerErrorIsNotInvalidGrant() {
        stubFor(post(urlEqualTo("/token")).willReturn(aResponse().withStatus(503).withBody("<html>Service Unavailable</html>")));

        assertFalse(refreshFails().getCause() instanceof InvalidGrantException);
    }
}

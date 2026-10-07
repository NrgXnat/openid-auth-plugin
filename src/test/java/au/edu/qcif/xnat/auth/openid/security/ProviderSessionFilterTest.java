package au.edu.qcif.xnat.auth.openid.security;

import org.junit.After;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.resource.OAuth2AccessDeniedException;
import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;
import org.springframework.security.oauth2.common.DefaultOAuth2RefreshToken;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.exceptions.InvalidClientException;
import org.springframework.security.oauth2.common.exceptions.InvalidGrantException;
import org.springframework.security.web.session.InvalidSessionStrategy;
import org.springframework.web.client.ResourceAccessException;

import java.util.Date;
import java.util.function.BiFunction;

import static au.edu.qcif.xnat.auth.openid.etc.OpenIdAuthConstant.PROVIDER_ID;
import static au.edu.qcif.xnat.auth.openid.security.ProviderSessionFilter.CHECK_AT_ATTR;
import static au.edu.qcif.xnat.auth.openid.security.ProviderSessionFilter.FALLBACK_INTERVAL_MILLIS;
import static au.edu.qcif.xnat.auth.openid.security.ProviderSessionFilter.REFRESH_TOKEN_ATTR;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;

@RunWith(MockitoJUnitRunner.class)
public class ProviderSessionFilterTest {

    private static final BiFunction<String, String, OAuth2AccessToken> NO_REFRESH = (providerId, refreshToken) -> {
        fail("the provider should not be contacted");
        return null;
    };

    @Mock private InvalidSessionStrategy endedSessionStrategy;

    private final MockHttpServletRequest  request  = new MockHttpServletRequest();
    private final MockHttpServletResponse response = new MockHttpServletResponse();
    private final MockFilterChain         chain    = new MockFilterChain();

    @After
    public void clearSecurityContext() {
        SecurityContextHolder.clearContext();
    }

    private ProviderSessionFilter filter(final BiFunction<String, String, OAuth2AccessToken> refresh) {
        return new ProviderSessionFilter(null) {
            @Override OAuth2AccessToken refresh(final String providerId, final String refreshToken) {
                return refresh.apply(providerId, refreshToken);
            }

            @Override InvalidSessionStrategy endedSessionStrategy() {
                return endedSessionStrategy;
            }
        };
    }

    /** A session signed in through provider "keycloak" with refresh token "rt-1", next checked at {@code checkAt}. */
    private MockHttpSession followingSession(final long checkAt) {
        final MockHttpSession session = new MockHttpSession();
        session.setAttribute(PROVIDER_ID, "keycloak");
        session.setAttribute(REFRESH_TOKEN_ATTR, "rt-1");
        session.setAttribute(CHECK_AT_ATTR, checkAt);
        request.setSession(session);
        return session;
    }

    private static OAuth2AccessToken token(final String refreshToken, final Date expiration) {
        final DefaultOAuth2AccessToken token = new DefaultOAuth2AccessToken("at");
        if (refreshToken != null) {
            token.setRefreshToken(new DefaultOAuth2RefreshToken(refreshToken));
        }
        token.setExpiration(expiration);
        return token;
    }

    private static OAuth2AccessDeniedException deniedBecause(final Exception cause) {
        return new OAuth2AccessDeniedException("Access token denied.", null, cause);
    }

    @Test
    public void requestWithoutSessionPassesThrough() throws Exception {
        filter(NO_REFRESH).doFilter(request, response, chain);

        assertNotNull(chain.getRequest());
    }

    @Test
    public void sessionNotFollowingAProviderPassesThrough() throws Exception {
        request.setSession(new MockHttpSession());

        filter(NO_REFRESH).doFilter(request, response, chain);

        assertNotNull(chain.getRequest());
    }

    @Test
    public void providerIsNotContactedBeforeTheAccessTokenExpires() throws Exception {
        followingSession(System.currentTimeMillis() + 60_000);

        filter(NO_REFRESH).doFilter(request, response, chain);

        assertNotNull(chain.getRequest());
    }

    @Test
    public void successfulRefreshKeepsTheSessionAndStoresTheNewToken() throws Exception {
        final MockHttpSession session = followingSession(System.currentTimeMillis() - 1);
        final Date expiration = new Date(System.currentTimeMillis() + 300_000);

        filter((providerId, refreshToken) -> {
            assertEquals("keycloak", providerId);
            assertEquals("rt-1", refreshToken);
            return token("rt-2", expiration);
        }).doFilter(request, response, chain);

        assertNotNull(chain.getRequest());
        assertFalse(session.isInvalid());
        assertEquals("rt-2", session.getAttribute(REFRESH_TOKEN_ATTR));
        assertEquals(expiration.getTime(), session.getAttribute(CHECK_AT_ATTR));
    }

    @Test
    public void refreshWithoutANewRefreshTokenKeepsTheCurrentOne() throws Exception {
        final MockHttpSession session = followingSession(System.currentTimeMillis() - 1);

        filter((providerId, refreshToken) -> token(null, new Date(System.currentTimeMillis() + 300_000)))
                .doFilter(request, response, chain);

        assertNotNull(chain.getRequest());
        assertEquals("rt-1", session.getAttribute(REFRESH_TOKEN_ATTR));
    }

    @Test
    public void rejectedRefreshTokenEndsTheSession() throws Exception {
        final MockHttpSession session = followingSession(System.currentTimeMillis() - 1);
        SecurityContextHolder.getContext().setAuthentication(new TestingAuthenticationToken("user", null, "ROLE_USER"));

        filter((providerId, refreshToken) -> {
            throw deniedBecause(new InvalidGrantException("Session not active"));
        }).doFilter(request, response, chain);

        assertNull("the request goes no further", chain.getRequest());
        assertTrue(session.isInvalid());
        assertNull(SecurityContextHolder.getContext().getAuthentication());
        verify(endedSessionStrategy).onInvalidSessionDetected(request, response);
    }

    @Test
    public void unreachableProviderKeepsTheSessionAndRetriesLater() throws Exception {
        final MockHttpSession session = followingSession(System.currentTimeMillis() - 1);
        final long before = System.currentTimeMillis();

        filter((providerId, refreshToken) -> {
            throw deniedBecause(new ResourceAccessException("Connection refused"));
        }).doFilter(request, response, chain);

        assertNotNull(chain.getRequest());
        assertFalse(session.isInvalid());
        assertEquals("rt-1", session.getAttribute(REFRESH_TOKEN_ATTR));
        assertTrue((Long) session.getAttribute(CHECK_AT_ATTR) >= before + FALLBACK_INTERVAL_MILLIS);
        verify(endedSessionStrategy, never()).onInvalidSessionDetected(any(), any());
    }

    @Test
    public void otherProviderErrorsKeepTheSession() throws Exception {
        final MockHttpSession session = followingSession(System.currentTimeMillis() - 1);

        filter((providerId, refreshToken) -> {
            throw deniedBecause(new InvalidClientException("Bad client credentials"));
        }).doFilter(request, response, chain);

        assertNotNull(chain.getRequest());
        assertFalse(session.isInvalid());
        verify(endedSessionStrategy, never()).onInvalidSessionDetected(any(), any());
    }

    @Test
    public void rememberStoresTheRefreshTokenAndWhenToCheck() {
        final MockHttpSession session = new MockHttpSession();
        final Date expiration = new Date(System.currentTimeMillis() + 300_000);

        ProviderSessionFilter.remember(session, "keycloak", token("rt-1", expiration));

        assertEquals("rt-1", session.getAttribute(REFRESH_TOKEN_ATTR));
        assertEquals(expiration.getTime(), session.getAttribute(CHECK_AT_ATTR));
    }

    @Test
    public void rememberWithoutARefreshTokenClearsOneFromAnEarlierSignIn() {
        final MockHttpSession session = new MockHttpSession();
        session.setAttribute(REFRESH_TOKEN_ATTR, "rt-old");
        session.setAttribute(CHECK_AT_ATTR, 1L);

        ProviderSessionFilter.remember(session, "keycloak", token(null, null));

        assertNull(session.getAttribute(REFRESH_TOKEN_ATTR));
        assertNull(session.getAttribute(CHECK_AT_ATTR));
    }
}

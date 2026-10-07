package au.edu.qcif.xnat.auth.openid.security;

import au.edu.qcif.xnat.auth.openid.OpenIdAuthPlugin;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.http.client.SimpleClientHttpRequestFactory;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.resource.OAuth2AccessDeniedException;
import org.springframework.security.oauth2.client.resource.OAuth2ProtectedResourceDetails;
import org.springframework.security.oauth2.client.token.DefaultAccessTokenRequest;
import org.springframework.security.oauth2.client.token.grant.code.AuthorizationCodeAccessTokenProvider;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.exceptions.InvalidGrantException;
import org.springframework.security.web.session.InvalidSessionStrategy;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.util.WebUtils;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;

import static au.edu.qcif.xnat.auth.openid.etc.OpenIdAuthConstant.PROVIDER_ID;

/**
 * Ties an XNAT session to the provider (SSO) session it was signed in with, for a provider that sets
 * {@code followProviderSession}. Sign-in keeps the provider's refresh token in the session (server-side only);
 * once the access token issued with it has expired, the next request refreshes it. A refresh the provider
 * rejects as {@code invalid_grant} means the provider session has ended — it timed out or reached its maximum
 * lifetime, or the user logged out of another application on the same provider — so the XNAT session is ended
 * too, and the request is handled like any other request carrying a dead session. A successful refresh counts
 * as activity at the provider, so working in XNAT keeps the provider session alive.
 *
 * <p>Any other failure (the provider unreachable, the client misconfigured) keeps the XNAT session and retries
 * after {@link #FALLBACK_INTERVAL_MILLIS}: a provider outage should not sign everyone out.</p>
 *
 * <p>Installed after the sign-in filter, which ends the chain on its own path, so a sign-in callback is never
 * checked against the session it is replacing.</p>
 */
@Slf4j
public class ProviderSessionFilter extends OncePerRequestFilter {

    /** Session attribute holding the provider's refresh token. Server-side only (never sent to the browser). */
    public static final String REFRESH_TOKEN_ATTR = "openIdRefreshToken";

    /** Session attribute holding the time (epoch millis) from which the provider session is next checked. */
    public static final String CHECK_AT_ATTR = "openIdProviderSessionCheckAt";

    /** Check interval when the provider gives no access-token expiry, and the retry delay after a failed check. */
    static final long FALLBACK_INTERVAL_MILLIS = 60_000L;

    private static final int TIMEOUT_MILLIS = 5_000;

    private final OpenIdAuthPlugin plugin;
    private final TokenRefresher refresher = new TokenRefresher();

    public ProviderSessionFilter(final OpenIdAuthPlugin plugin) {
        this.plugin = plugin;
    }

    /**
     * Records how to check the provider session behind a new sign-in: the refresh token, and when the access
     * token issued with it expires. With no refresh token there is nothing to check with, so any left in the
     * session by an earlier sign-in is removed rather than checked against this one.
     */
    public static void remember(final HttpSession session, final String providerId, final OAuth2AccessToken token) {
        if (token.getRefreshToken() == null) {
            log.warn("Provider '{}' issued no refresh token, so this XNAT session cannot follow the provider session", providerId);
            session.removeAttribute(REFRESH_TOKEN_ATTR);
            session.removeAttribute(CHECK_AT_ATTR);
            return;
        }
        session.setAttribute(REFRESH_TOKEN_ATTR, token.getRefreshToken().getValue());
        session.setAttribute(CHECK_AT_ATTR, nextCheck(token));
    }

    @Override
    protected void doFilterInternal(final HttpServletRequest request, final HttpServletResponse response, final FilterChain chain)
            throws ServletException, IOException {
        final HttpSession session = request.getSession(false);
        if (session != null && session.getAttribute(REFRESH_TOKEN_ATTR) != null && providerSessionEnded(session)) {
            session.invalidate();
            SecurityContextHolder.clearContext();
            endedSessionStrategy().onInvalidSessionDetected(request, response);
            return;
        }
        chain.doFilter(request, response);
    }

    /** What to do with the request once its session has been ended; isolated here so tests can override it. */
    InvalidSessionStrategy endedSessionStrategy() {
        return new LogoutRedirectInvalidSessionStrategy();
    }

    /** Exchanges the refresh token at the provider; isolated here so tests can override it. */
    OAuth2AccessToken refresh(final String providerId, final String refreshToken) {
        return refresher.refresh(plugin.getProtectedResourceDetails(providerId), refreshToken);
    }

    private boolean providerSessionEnded(final HttpSession session) {
        // Requests arriving together once the token has expired would otherwise each spend the refresh token.
        synchronized (WebUtils.getSessionMutex(session)) {
            final Long checkAt = (Long) session.getAttribute(CHECK_AT_ATTR);
            if (checkAt != null && System.currentTimeMillis() < checkAt) {
                return false;
            }
            final String providerId = (String) session.getAttribute(PROVIDER_ID);
            try {
                final OAuth2AccessToken refreshed = refresh(providerId, (String) session.getAttribute(REFRESH_TOKEN_ATTR));
                // A provider that doesn't rotate refresh tokens returns none; the current one stays valid.
                if (refreshed.getRefreshToken() != null) {
                    session.setAttribute(REFRESH_TOKEN_ATTR, refreshed.getRefreshToken().getValue());
                }
                session.setAttribute(CHECK_AT_ATTR, nextCheck(refreshed));
                return false;
            } catch (final OAuth2AccessDeniedException e) {
                if (e.getCause() instanceof InvalidGrantException) {
                    log.info("Provider '{}' rejected the session's refresh token ({}); ending the XNAT session",
                             providerId, e.getCause().getMessage());
                    return true;
                }
                log.warn("Could not check the session at provider '{}'; keeping the XNAT session and retrying in {}s",
                         providerId, FALLBACK_INTERVAL_MILLIS / 1000, e);
                session.setAttribute(CHECK_AT_ATTR, System.currentTimeMillis() + FALLBACK_INTERVAL_MILLIS);
                return false;
            }
        }
    }

    private static long nextCheck(final OAuth2AccessToken token) {
        return token.getExpiration() != null
               ? token.getExpiration().getTime()
               : System.currentTimeMillis() + FALLBACK_INTERVAL_MILLIS;
    }

    /**
     * Makes the refresh-token request to the provider's token endpoint. The library's own
     * {@code refreshAccessToken} turns every failure into a redirect to sign in; this keeps the cause, so a
     * refresh token the provider rejected ({@link InvalidGrantException}) can be told apart from a provider
     * that couldn't be reached.
     */
    static class TokenRefresher extends AuthorizationCodeAccessTokenProvider {
        TokenRefresher() {
            final SimpleClientHttpRequestFactory requestFactory = new SimpleClientHttpRequestFactory();
            requestFactory.setConnectTimeout(TIMEOUT_MILLIS);
            requestFactory.setReadTimeout(TIMEOUT_MILLIS);
            setRequestFactory(requestFactory);
        }

        OAuth2AccessToken refresh(final OAuth2ProtectedResourceDetails resource, final String refreshToken) {
            final MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
            form.add("grant_type", "refresh_token");
            form.add("refresh_token", refreshToken);
            return retrieveToken(new DefaultAccessTokenRequest(), resource, form, new HttpHeaders());
        }
    }
}

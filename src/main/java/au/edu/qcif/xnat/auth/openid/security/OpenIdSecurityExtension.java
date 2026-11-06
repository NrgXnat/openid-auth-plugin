package au.edu.qcif.xnat.auth.openid.security;

import au.edu.qcif.xnat.auth.openid.bearer.BearerTokenAuthenticationFilter;
import au.edu.qcif.xnat.auth.openid.OpenIdAuthPlugin;
import au.edu.qcif.xnat.auth.openid.OpenIdConnectFilter;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.nrg.xnat.security.BaseXnatSecurityExtension;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.client.filter.OAuth2ClientContextFilter;
import org.springframework.security.web.authentication.preauth.AbstractPreAuthenticatedProcessingFilter;
import org.springframework.security.web.session.InvalidSessionStrategy;
import org.springframework.stereotype.Component;

import static au.edu.qcif.xnat.auth.openid.etc.OpenIdAuthConstant.LOGOUT_URI;
import static au.edu.qcif.xnat.auth.openid.etc.OpenIdAuthConstant.SESSION_ON_INVALID;
import static org.nrg.xdat.services.XdatUserAuthService.OPENID;

@Slf4j
@Component
public class OpenIdSecurityExtension extends BaseXnatSecurityExtension {
    final OpenIdAuthPlugin openIdAuthPlugin;
    final OpenIdConnectFilter openIdConnectFilter;
    final BearerTokenAuthenticationFilter bearerTokenAuthenticationFilter;

    public OpenIdSecurityExtension(final OpenIdAuthPlugin openIdAuthPlugin,
                                   final OpenIdConnectFilter openIdConnectFilter,
                                   final BearerTokenAuthenticationFilter bearerTokenAuthenticationFilter) {
        this.openIdAuthPlugin = openIdAuthPlugin;
        this.openIdConnectFilter = openIdConnectFilter;
        this.bearerTokenAuthenticationFilter = bearerTokenAuthenticationFilter;
    }

    @Override
    @SuppressWarnings("deprecation")
    public void configure(final HttpSecurity http) {
        try {
            if (!openIdAuthPlugin.getProps().isEmpty()) {
                // The bearer filter (when any provider opts in) runs before the redirect-oriented
                // interactive filters: it authenticates Authorization: Bearer REST requests and
                // short-circuits, and is a no-op for everything else. It runs after Spring's
                // SecurityContextPersistenceFilter, so an already-authenticated session is honored.
                if (hasAnyBearerProvider()) {
                    http.addFilterAfter(bearerTokenAuthenticationFilter, AbstractPreAuthenticatedProcessingFilter.class)
                            .addFilterAfter(new OAuth2ClientContextFilter(), BearerTokenAuthenticationFilter.class)
                            .addFilterAfter(openIdConnectFilter, OAuth2ClientContextFilter.class);
                } else {
                    http.addFilterAfter(new OAuth2ClientContextFilter(), AbstractPreAuthenticatedProcessingFilter.class)
                            .addFilterAfter(openIdConnectFilter, OAuth2ClientContextFilter.class);
                }
                configureLogoutAndTimeout(http);
            }
        } catch (Throwable e) {
            log.error("An error occurred trying to create and/or configure the OAuth2ClientContextFilter and OpenIdConnectFilter", e);
        }
    }

    /**
     * Wires logout and session-timeout behaviour for auto-login (only when a provider has
     * {@code autoLogin} enabled). Installs {@link OpenIdLogoutHandler} (the cookie safety net + id_token
     * capture that stops a logout from immediately bouncing the user back in), and — because an idle timeout
     * would otherwise be undone by an automatic re-login — a {@link LogoutRedirectInvalidSessionStrategy} that
     * routes an expired-session request to logout, or with {@code session.onInvalid=reauth} a
     * {@link ReauthInvalidSessionStrategy} that sends page loads back through auto-login instead. When the provider
     * also sets {@code logoutUri}, logout (and hence timeout) performs RP-Initiated Logout to end the provider (SSO)
     * session — the platform-standard behaviour.
     */
    private void configureLogoutAndTimeout(final HttpSecurity http) throws Exception {
        final String autoLoginProvider = openIdAuthPlugin.getAutoLoginProviderId();
        if (autoLoginProvider == null) {
            return;
        }
        // Clear the stale session cookie on logout, so an expired-session redirect to logout is one-shot and
        // a leftover JSESSIONID can't be mistaken for an expired session on a later fresh visit.
        http.logout().deleteCookies("JSESSIONID").addLogoutHandler(new OpenIdLogoutHandler(openIdAuthPlugin));

        // An idle "auto-logout" arrives as a request with an expired session id. Spring Security detects it on
        // the original request (before XNAT recreates a session for the login redirect, which is why the login
        // screen is too late) and this strategy decides between logout and signing in again.
        http.sessionManagement().invalidSessionStrategy(invalidSessionStrategy(autoLoginProvider));

        final String endSessionUri = openIdAuthPlugin.getProperty(autoLoginProvider, LOGOUT_URI);
        if (StringUtils.isNotBlank(endSessionUri)) {
            final String clientId = openIdAuthPlugin.getProperty(autoLoginProvider, "clientId");
            http.logout().logoutSuccessHandler(new RpInitiatedLogoutSuccessHandler(endSessionUri, clientId));
            log.debug("RP-initiated logout enabled for provider '{}'", autoLoginProvider);
        }
    }

    /**
     * {@code logout} (the default) treats an unrecognised session as a timeout to enforce; {@code reauth} hands page
     * loads back to auto-login, for a deployment where the provider session decides whether the user is signed in.
     */
    private InvalidSessionStrategy invalidSessionStrategy(final String providerId) {
        final String onInvalid = StringUtils.defaultIfBlank(openIdAuthPlugin.getProperty(providerId, SESSION_ON_INVALID), "logout").trim();
        switch (onInvalid) {
            case "reauth":
                log.debug("Expired sessions on page loads sign in again through provider '{}'", providerId);
                return new ReauthInvalidSessionStrategy();
            case "logout":
                return new LogoutRedirectInvalidSessionStrategy();
            default:
                log.warn("Unknown {} '{}' for provider '{}'; using 'logout'", SESSION_ON_INVALID, onInvalid, providerId);
                return new LogoutRedirectInvalidSessionStrategy();
        }
    }

    /** True if at least one configured provider opts into the bearer-token path. */
    private boolean hasAnyBearerProvider() {
        return openIdAuthPlugin.getEnabledProviders().stream()
                .anyMatch(providerId -> Boolean.parseBoolean(openIdAuthPlugin.getProperty(providerId, "bearer.enabled")));
    }

    public String getAuthMethod() {
        return OPENID;
    }
}

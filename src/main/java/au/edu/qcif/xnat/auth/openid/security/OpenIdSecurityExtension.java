package au.edu.qcif.xnat.auth.openid.security;

import au.edu.qcif.xnat.auth.openid.BearerTokenAuthenticationFilter;
import au.edu.qcif.xnat.auth.openid.OpenIdAuthPlugin;
import au.edu.qcif.xnat.auth.openid.OpenIdConnectFilter;
import lombok.extern.slf4j.Slf4j;
import org.nrg.xnat.security.BaseXnatSecurityExtension;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.client.filter.OAuth2ClientContextFilter;
import org.springframework.security.web.authentication.preauth.AbstractPreAuthenticatedProcessingFilter;
import org.springframework.stereotype.Component;

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
            }
        } catch (Throwable e) {
            log.error("An error occurred trying to create and/or configure the OAuth2ClientContextFilter and OpenIdConnectFilter", e);
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

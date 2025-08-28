package au.edu.qcif.xnat.auth.openid.security;

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

    public OpenIdSecurityExtension(final OpenIdAuthPlugin openIdAuthPlugin,
                                   final OpenIdConnectFilter openIdConnectFilter) {
        this.openIdAuthPlugin = openIdAuthPlugin;
        this.openIdConnectFilter = openIdConnectFilter;
    }

    @Override
    @SuppressWarnings("deprecation")
    public void configure(final HttpSecurity http) {
        try {
            if (!openIdAuthPlugin.getProps().isEmpty()) {
                http.addFilterAfter(new OAuth2ClientContextFilter(), AbstractPreAuthenticatedProcessingFilter.class)
                        .addFilterAfter(openIdConnectFilter, OAuth2ClientContextFilter.class);
            }
        } catch (Throwable e) {
            log.error("An error occurred trying to create and/or configure the OAuth2ClientContextFilter and OpenIdConnectFilter", e);
        }
    }

    public String getAuthMethod() {
        return OPENID;
    }
}

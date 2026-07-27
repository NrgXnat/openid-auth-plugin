/*
 *Copyright (C) 2018 Queensland Cyber Infrastructure Foundation (http://www.qcif.edu.au/)
 *
 *This program is free software: you can redistribute it and/or modify
 *it under the terms of the GNU General Public License as published by
 *the Free Software Foundation; either version 2 of the License, or
 *(at your option) any later version.
 *
 *This program is distributed in the hope that it will be useful,
 *but WITHOUT ANY WARRANTY; without even the implied warranty of
 *MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *GNU General Public License for more details.
 *
 *You should have received a copy of the GNU General Public License along
 *with this program; if not, write to the Free Software Foundation, Inc.,
 *51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */
package au.edu.qcif.xnat.auth.openid;

import au.edu.qcif.xnat.auth.openid.pkce.PkceAuthorizationCodeAccessTokenProvider;
import au.edu.qcif.xnat.auth.openid.pkce.PkceAuthorizationCodeResourceDetails;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.nrg.framework.annotations.XnatPlugin;
import org.nrg.xdat.preferences.SiteConfigPreferences;
import org.nrg.xnat.security.provider.AuthenticationProviderConfigurationLocator;
import org.nrg.xnat.security.provider.ProviderAttributes;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Scope;
import org.springframework.context.annotation.ScopedProxyMode;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.oauth2.client.OAuth2ClientContext;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;
import org.springframework.security.oauth2.client.token.AccessTokenProvider;
import org.springframework.security.oauth2.client.token.AccessTokenProviderChain;
import org.springframework.security.oauth2.client.token.grant.client.ClientCredentialsAccessTokenProvider;
import org.springframework.security.oauth2.client.token.grant.code.AuthorizationCodeResourceDetails;
import org.springframework.security.oauth2.client.token.grant.implicit.ImplicitAccessTokenProvider;
import org.springframework.security.oauth2.client.token.grant.password.ResourceOwnerPasswordAccessTokenProvider;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableOAuth2Client;
import org.springframework.web.context.WebApplicationContext;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import javax.servlet.http.HttpServletRequest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.Set;
import java.util.stream.Collectors;

import static au.edu.qcif.xnat.auth.openid.etc.OpenIdAuthConstant.AUTO_LOGIN;
import static au.edu.qcif.xnat.auth.openid.etc.OpenIdAuthConstant.DEFAULT_REDIR_URI;
import static au.edu.qcif.xnat.auth.openid.etc.OpenIdAuthConstant.KEY_REDIR_URI;
import static au.edu.qcif.xnat.auth.openid.etc.OpenIdAuthConstant.PKCE_ENABLED;
import static au.edu.qcif.xnat.auth.openid.service.KeystoreServiceImpl.ID_TOKEN_ENCRYPTION_ALG_PROPERTY;
import static org.nrg.xdat.services.XdatUserAuthService.OPENID;

/**
 * XNAT Authentication plugin.
 *
 * @author <a href="https://github.com/shilob">Shilo Banihit</a>
 */
@SuppressWarnings("deprecation")
@XnatPlugin(value = "openIdAuthPlugin",
        name = "XNAT OpenID Authentication Provider Plugin",
        logConfigurationFile = "au/edu/qcif/xnat/auth/openid/openid-auth-plugin-logback.xml",
        openUrls = {"/xapi/openid/.well-known/jwks.json", "/xapi/openid/legal/terms-of-service", "/xapi/openid/legal/privacy-policy"})
@EnableWebSecurity
@EnableOAuth2Client
@ComponentScan({"au.edu.qcif.xnat.auth.openid"})
@Slf4j
public class OpenIdAuthPlugin {

    private final AuthenticationProviderConfigurationLocator _locator;
    private final SiteConfigPreferences _siteConfigPreferences;
    private final Properties _props = new Properties();
    private final List<String> _openIdProviders = new ArrayList<>();

    @Value("${openid.state-key-length:16}")
    private int stateKeyLength;

    public OpenIdAuthPlugin(final AuthenticationProviderConfigurationLocator locator,
                            final SiteConfigPreferences siteConfigPreferences) {
        _locator = locator;
        _siteConfigPreferences = siteConfigPreferences;
        setup();
    }

    public boolean isEnabled(final String providerId) {
        return _openIdProviders.contains(providerId);
    }

    public String getProperty(String providerId, String propName) {
        return _props.getProperty(String.join(".", OPENID, providerId, propName));
    }

    public String getProperty(String propName) {
        return _props.getProperty(String.join(".", OPENID, propName));
    }

    public Properties getProps() {
        return _props;
    }

    public String getRedirectUri() {
        return StringUtils.prependIfMissing(_props.getProperty(KEY_REDIR_URI, DEFAULT_REDIR_URI), "/");
    }

    /**
     * Gets the auto-enabled setting for the specified provider from the standard XNAT provider attributes.
     * This determines whether new users created through this provider should be automatically enabled.
     *
     * @param providerId The provider ID
     * @return true if users should be auto-enabled, false otherwise
     */
    public boolean isAutoEnabled(String providerId) {
        final ProviderAttributes providerDefinition = _locator.getProviderDefinition(providerId);
        return providerDefinition != null && providerDefinition.isAutoEnabled();
    }

    /**
     * Gets the auto-verified setting for the specified provider from the standard XNAT provider attributes.
     * This determines whether new users created through this provider should be automatically verified.
     *
     * @param providerId The provider ID
     * @return true if users should be auto-verified, false otherwise
     */
    public boolean isAutoVerified(String providerId) {
        final ProviderAttributes providerDefinition = _locator.getProviderDefinition(providerId);
        return providerDefinition != null && providerDefinition.isAutoVerified();
    }

    public Set<String> getAllConfiguredIdTokenEncryptionAlgorithms() {
        return _props.entrySet().stream()
                .filter(e -> {
                    final String key = e.getKey().toString();
                    return key.startsWith(OPENID + ".") && key.endsWith(ID_TOKEN_ENCRYPTION_ALG_PROPERTY);
                })
                .map(e -> e.getValue().toString())
                .filter(StringUtils::isNotBlank)
                .map(String::trim)
                .collect(Collectors.toSet());
    }

    public List<String> getEnabledProviders() {
        return _openIdProviders;
    }

    /**
     * Returns the id of the enabled provider that opts into auto-login on the login page
     * ({@code openid.<providerId>.autoLogin=true}), or {@code null} if none do. Auto-login can only
     * target a single identity provider, so if more than one opts in the first enabled one is used and a
     * warning is logged.
     *
     * @return the auto-login provider id, or {@code null} if the feature is not enabled for any provider.
     */
    public String getAutoLoginProviderId() {
        final List<String> autoLoginProviders = _openIdProviders.stream()
                .filter(providerId -> Boolean.parseBoolean(getProperty(providerId, AUTO_LOGIN)))
                .collect(Collectors.toList());
        if (autoLoginProviders.isEmpty()) {
            return null;
        }
        if (autoLoginProviders.size() > 1) {
            log.warn("More than one provider has {} enabled ({}); using '{}' for auto-login.",
                    AUTO_LOGIN, autoLoginProviders, autoLoginProviders.get(0));
        }
        return autoLoginProviders.get(0);
    }

    @Bean
    public AccessTokenProvider accessTokenProvider() {
        return new AccessTokenProviderChain(Arrays.<AccessTokenProvider>asList(new PkceAuthorizationCodeAccessTokenProvider(stateKeyLength),
                                                                               new ImplicitAccessTokenProvider(),
                                                                               new ResourceOwnerPasswordAccessTokenProvider(),
                                                                               new ClientCredentialsAccessTokenProvider()));
    }

    @Bean
    @Scope(value = WebApplicationContext.SCOPE_SESSION, proxyMode = ScopedProxyMode.TARGET_CLASS)
    public OAuth2RestTemplate restTemplate(final OAuth2ClientContext clientContext) {
        log.debug("At create rest template...");
        final HttpServletRequest request = ((ServletRequestAttributes) RequestContextHolder.currentRequestAttributes()).getRequest();
        // Interrogate request to get providerId (e.g. look at url if nothing
        // else)
        String providerId = request.getParameter("providerId");
        log.debug("Provider id is: {}", providerId);
        request.getSession().setAttribute("providerId", providerId);
        final OAuth2RestTemplate template = new OAuth2RestTemplate(getProtectedResourceDetails(providerId), clientContext);
        template.setAccessTokenProvider(accessTokenProvider());
        return template;
    }

    public AuthorizationCodeResourceDetails getProtectedResourceDetails(final String providerId) {
        log.debug("Creating protected resource details of provider: {}", providerId);
        final String       clientId          = getProperty(providerId, "clientId");
        final String       clientSecret      = getProperty(providerId, "clientSecret");
        final String       accessTokenUri    = getProperty(providerId, "accessTokenUri");
        final String       userAuthUri       = getProperty(providerId, "userAuthUri");
        final String       preEstablishedUri = StringUtils.stripEnd(StringUtils.getIfBlank(getProps().getProperty("siteUrl"), _siteConfigPreferences::getSiteUrl), "/") + getRedirectUri();
        final List<String> scopes            = Arrays.asList(StringUtils.split(getProperty(providerId, "scopes"), ", "));

        final PkceAuthorizationCodeResourceDetails details = new PkceAuthorizationCodeResourceDetails();
        details.setClientId(clientId);
        details.setClientSecret(clientSecret);
        details.setAccessTokenUri(accessTokenUri);
        details.setUserAuthorizationUri(userAuthUri);
        details.setScope(scopes);
        details.setPreEstablishedRedirectUri(preEstablishedUri);
        details.setUseCurrentUri(false);
        details.setPkceEnabled(isPkceEnabled(providerId));
        return details;
    }

    private boolean isPkceEnabled(final String providerId) {
        final boolean pkceEnabled = Boolean.parseBoolean(getProperty(providerId, PKCE_ENABLED));
        log.debug("Is PKCE Enabled: {}", pkceEnabled);
        return pkceEnabled;
    }

    private void setup() {
        final Map<String, ProviderAttributes> openIdProviders = _locator.getProviderDefinitionsByAuthMethod("openid");
        if (openIdProviders.isEmpty()) {
            log.error("There are no OpenID providers configured");
            return;
        }

        //Collate properties across all property definitions to facilitate multiple open id prop file
        openIdProviders.forEach((providerId, v) -> {
            _openIdProviders.add(providerId);
            final ProviderAttributes providerDefinition = _locator.getProviderDefinition(providerId);
            if (providerDefinition != null) {
                _props.putAll(providerDefinition.getProperties());
            } else {
                log.error("I can't find the provider definition for that ID: {}", providerId);
            }
        });

        if (_props.isEmpty()) {
            log.error("Could not set properties for available providers. Check the auth property files");
        }
    }

}

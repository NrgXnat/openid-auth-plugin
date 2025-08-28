package au.edu.qcif.xnat.auth.openid;

import au.edu.qcif.xnat.auth.openid.etc.OpenIdAuthConstant;
import au.edu.qcif.xnat.auth.openid.service.KeystoreService;
import au.edu.qcif.xnat.auth.openid.service.KeystoreServiceImpl;
import lombok.extern.slf4j.Slf4j;
import org.nrg.framework.configuration.ConfigPaths;
import org.nrg.framework.configuration.SerializerConfig;
import org.nrg.framework.services.ContextService;
import org.nrg.prefs.services.NrgPreferenceService;
import org.nrg.xdat.preferences.SiteConfigPreferences;
import org.nrg.xdat.security.services.UserManagementServiceI;
import org.nrg.xdat.services.XdatUserAuthService;
import org.nrg.xft.security.UserI;
import org.nrg.xnat.security.provider.AuthenticationProviderConfigurationLocator;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.core.io.ClassPathResource;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.authentication.AuthenticationEventPublisher;
import org.springframework.security.oauth2.client.DefaultOAuth2ClientContext;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;
import org.springframework.security.oauth2.client.token.AccessTokenRequest;
import org.springframework.security.oauth2.client.token.DefaultAccessTokenRequest;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import java.io.IOException;
import java.nio.file.Paths;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@SuppressWarnings("deprecation")
@Configuration
@Import(SerializerConfig.class)
@Slf4j
public class OpenIdConnectFilterTestConfig {
    public static final String TEST_PROVIDER_ID = "test";
    public static final String TEST_USERNAME = "test_1234567890";
    public static final String STATE = "state";
    public static final String CSRF_STATE = "CSRF-state";
    public static final String TEST_ACCESS_TOKEN = "test-token";

    @Bean
    public ContextService contextService() {
        return new ContextService();
    }

    @Bean
    public AuthenticationSuccessHandler authenticationSuccessHandler() {
        return (request, response, authentication) -> log.info("Handling successful authentication");
    }

    @Bean
    public AuthenticationFailureHandler authenticationFailureHandler() {
        return (request, response, authentication) -> log.info("Handling failed authentication");
    }

    @Bean
    public SessionAuthenticationStrategy sessionAuthenticationStrategy() {
        return (request, response, authentication) -> log.info("Handling authentication strategy");
    }

    @Bean
    public NrgPreferenceService nrgPreferenceService() {
        return mock(NrgPreferenceService.class);
    }

    @Bean
    public SiteConfigPreferences siteConfigPreferences() {
        final SiteConfigPreferences siteConfigPreferences = mock(SiteConfigPreferences.class);
        when(siteConfigPreferences.getEmailVerification()).thenReturn(true);
        when(siteConfigPreferences.getSiteUrl()).thenReturn("http://localhost");
        return siteConfigPreferences;
    }

    @Bean
    public XdatUserAuthService userAuthService() {
        final UserI user = mock(UserI.class);
        when(user.getUsername()).thenReturn(TEST_USERNAME);
        when(user.getLogin()).thenReturn(TEST_USERNAME);
        when(user.isEnabled()).thenReturn(true);
        when(user.isVerified()).thenReturn(true);
        when(user.isAccountNonLocked()).thenReturn(true);

        final XdatUserAuthService userAuthService = mock(XdatUserAuthService.class);
        when(userAuthService.getUserDetailsByNameAndAuth(TEST_USERNAME, XdatUserAuthService.OPENID, TEST_PROVIDER_ID)).thenReturn(user);
        return userAuthService;
    }

    @Bean
    public UserManagementServiceI userManagementService() {
        final UserManagementServiceI service = mock(UserManagementServiceI.class);
        doNothing().when(service).clearCache(any(UserI.class));
        return service;
    }

    @Bean
    public KeystoreService keystoreService() {
        return mock(KeystoreServiceImpl.class);
    }

    @Bean
    public AuthenticationEventPublisher authenticationEventPublisher() {
        return mock(AuthenticationEventPublisher.class);
    }

    @Bean
    public OpenIdAuthPlugin openIdAuthPlugin(final SiteConfigPreferences siteConfigPreferences) throws IOException {
        final ConfigPaths configPaths = new ConfigPaths(Collections.singletonList(Paths.get(new ClassPathResource("config").getURI())));
        final AuthenticationProviderConfigurationLocator locator = new AuthenticationProviderConfigurationLocator(configPaths, null);
        return new OpenIdAuthPlugin(locator, siteConfigPreferences);
    }

    @Bean
    public OAuth2RestTemplate restTemplate(final OpenIdAuthPlugin plugin) {
        final MockHttpServletRequest mockRequest = new MockHttpServletRequest();
        mockRequest.setParameter(OpenIdAuthConstant.PROVIDER_ID, TEST_PROVIDER_ID);
        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(mockRequest));

        final Map<String, String[]> parameters = new HashMap<>();
        parameters.put(STATE, new String[]{CSRF_STATE});

        final AccessTokenRequest accessTokenRequest = new DefaultAccessTokenRequest(parameters);
        accessTokenRequest.setPreservedState(CSRF_STATE);

        final DefaultOAuth2ClientContext clientContext = new DefaultOAuth2ClientContext(accessTokenRequest);
        clientContext.setPreservedState(CSRF_STATE, CSRF_STATE);

        return plugin.restTemplate(clientContext);
    }

    @Bean
    public OpenIdConnectFilter openIdConnectFilter(final SiteConfigPreferences siteConfigPreferences,
                                                   final KeystoreService keystoreService,
                                                   final OpenIdAuthPlugin openIdAuthPlugin,
                                                   final AuthenticationEventPublisher authenticationEventPublisher) {
        return new OpenIdConnectFilter(openIdAuthPlugin, authenticationEventPublisher, userAuthService(), siteConfigPreferences, keystoreService);
    }
}

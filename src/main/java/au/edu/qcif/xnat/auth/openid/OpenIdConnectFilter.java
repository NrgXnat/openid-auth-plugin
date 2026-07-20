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

import au.edu.qcif.xnat.auth.openid.gate.AuthPath;
import au.edu.qcif.xnat.auth.openid.gate.ClaimGate;
import au.edu.qcif.xnat.auth.openid.gate.ClaimGateException;
import au.edu.qcif.xnat.auth.openid.gate.ClaimGateFactory;
import au.edu.qcif.xnat.auth.openid.gate.TokenContext;
import au.edu.qcif.xnat.auth.openid.service.KeystoreService;
import au.edu.qcif.xnat.auth.openid.tokens.OpenIdAuthRequestToken;
import au.edu.qcif.xnat.auth.openid.tokens.OpenIdAuthToken;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.crypto.RSADecrypter;
import com.nimbusds.jwt.EncryptedJWT;
import com.nimbusds.jwt.SignedJWT;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.collections.MapUtils;
import org.apache.commons.lang3.StringUtils;
import org.nrg.framework.generics.GenericUtils;
import org.nrg.xapi.exceptions.NotFoundException;
import org.nrg.xdat.exceptions.UsernameAuthMappingNotFoundException;
import org.nrg.xdat.preferences.SiteConfigPreferences;
import org.nrg.xdat.security.helpers.UserHelper;
import org.nrg.xdat.services.XdatUserAuthService;
import org.nrg.xdat.turbine.utils.AccessLogger;
import org.nrg.xdat.turbine.utils.TurbineUtils;
import org.nrg.xft.security.UserI;
import org.nrg.xnat.security.exceptions.NewAutoAccountNotAutoEnabledException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.AuthenticationEventPublisher;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.CredentialsExpiredException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.exceptions.OAuth2Exception;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableOAuth2Client;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;
import org.springframework.stereotype.Component;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.text.ParseException;
import java.util.Collections;
import java.util.Map;
import java.util.stream.Collectors;
import au.edu.qcif.xnat.auth.openid.utils.OpenIdUtils;
import org.nrg.xdat.XDAT;
import org.nrg.xnat.security.OnXnatLogin;
import org.springframework.beans.factory.annotation.Qualifier;
import java.util.Optional;

/**
 * Main Spring Security authentication filter.
 *
 * @author <a href="https://github.com/shilob">Shilo Banihit</a>
 */
@SuppressWarnings("deprecation")
@EnableOAuth2Client
@Slf4j
@Component
public class OpenIdConnectFilter extends AbstractAuthenticationProcessingFilter {

    /**
     * Session attribute key for storing OpenID error messages to display on the login page.
     */
    public static final String OPENID_ERROR_MESSAGE = "openIdErrorMessage";

    private final OpenIdAuthPlugin _plugin;
    private final AuthenticationEventPublisher _eventPublisher;
    private final KeystoreService _keystoreService;
    private final ClaimGateFactory _gateFactory;
    private final OpenIdUserResolver _userResolver;
    private final OpenIdAccountPolicy _accountPolicy;

    private OAuth2RestTemplate _restTemplate;

    private static final String DEFAULT_REDIRECT_URI = "/openid/callback";
    private static final String USER_INFO_URI = "userInfoUri";

    public OpenIdConnectFilter(@Qualifier(OpenIdUtils.ALTERNATE_SUCCESS_HANDLER) Optional<AuthenticationSuccessHandler> oidcSuccessHandler,
                               final OpenIdAuthPlugin plugin,
                               final AuthenticationEventPublisher eventPublisher,
                               final XdatUserAuthService userAuthService,
                               final SiteConfigPreferences siteConfigPreferences,
                               final KeystoreService keystoreService) {
        super(StringUtils.defaultIfBlank(plugin.getProps().getProperty(PRE_ESTABLISHED_REDIRECT_URI_PROPERTY), DEFAULT_REDIRECT_URI));
        OnXnatLogin onXnatLogin = XDAT.getContextService().getBean(OnXnatLogin.class);
        super.setAuthenticationSuccessHandler(oidcSuccessHandler.orElse(onXnatLogin));

        log.debug("Creating filter for URL {}", StringUtils.defaultIfBlank(plugin.getProps().getProperty(PRE_ESTABLISHED_REDIRECT_URI_PROPERTY), DEFAULT_REDIRECT_URI));
        setAuthenticationManager(new NoopAuthenticationManager());
        _plugin = plugin;
        _eventPublisher = eventPublisher;
        _keystoreService = keystoreService;
        _gateFactory = new ClaimGateFactory(plugin);
        _userResolver = new OpenIdUserResolver(plugin, userAuthService);
        _accountPolicy = new OpenIdAccountPolicy(plugin, siteConfigPreferences);
    }


    @Autowired
    @Override
    public void setAuthenticationFailureHandler(final AuthenticationFailureHandler handler) {
        super.setAuthenticationFailureHandler(handler);
    }

    @Autowired
    @Override
    public void setSessionAuthenticationStrategy(final SessionAuthenticationStrategy strategy) {
        super.setSessionAuthenticationStrategy(strategy);
    }

    @Autowired
    public void setOAuth2RestTemplate(final OAuth2RestTemplate restTemplate) {
        _restTemplate = restTemplate;
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException, IOException {
        log.debug("Executed attemptAuthentication...");

        HttpSession session = request.getSession(false);
        if (session != null) {
            String requestProviderId = request.getParameter("providerId");
            String sessionProviderId = (String) request.getSession().getAttribute("providerId");
            if (requestProviderId != null && !requestProviderId.equals(sessionProviderId)) {
                log.debug("Found a session that had previously stopped during the OAuth/OIDC authentication process. Deleting the session.");
                request.getSession().invalidate();
            }
        }

        OAuth2AccessToken accessToken;
        try {
            log.debug("Getting access token...");
            accessToken = _restTemplate.getAccessToken();
            log.debug("Got access token!!! {}", accessToken);
        } catch (final OAuth2Exception e) {
            log.debug("Could not obtain access token", e);
            log.debug("<<---------------------------->>");
            throw new BadCredentialsException("Could not obtain access token", e);
        } catch (final RuntimeException ex2) {
            log.debug("Runtime exception", ex2);
            log.debug("----------------------------");
            throw ex2;
        }

        String providerId = (String) request.getSession().getAttribute("providerId");

        log.debug("Getting idToken...");
        final String idToken = accessToken.getAdditionalInformation().get("id_token").toString().trim();

        final TokenContext tokenContext;
        try {
            tokenContext = parseIdToken(idToken, providerId);
        } catch (JOSEException | ParseException e) {
            log.error("An unexpected error occurred attempting to parse id_token", e);
            throw new BadCredentialsException("Failed to parse id_token", e);
        } catch (NotFoundException e) {
            log.error("Provider id {} not configured", providerId, e);
            throw new BadCredentialsException("Provider not configured", e);
        }

        applyIdTokenClaimGates(providerId, tokenContext);

        final Map<String, Object> authInfo = tokenContext.claims().getClaims().entrySet().stream()
                .collect(Collectors.toMap(
                        Map.Entry::getKey,
                        e -> e.getValue() != null ? e.getValue() : ""
                ));

        log.debug("===== : {}", authInfo);
        final String userInfoUri = _plugin.getProperty(providerId, USER_INFO_URI);

        if (!StringUtils.isEmpty(userInfoUri)) {
            Map<String, Object> userInfo = getUserInfo(accessToken.getValue(), userInfoUri);
            authInfo.putAll(userInfo);
        }

        final OpenIdConnectUserDetails user;
        try {
            user = new OpenIdConnectUserDetails(providerId, authInfo, accessToken, _plugin);
        } catch (IllegalArgumentException e) {
            log.error("OpenID authentication failed for provider '{}'", providerId, e);
            throw new BadCredentialsException(e.getMessage(), e);
        }

        if (_accountPolicy.shouldFilterEmailDomains(providerId) && !_accountPolicy.isEmailDomainAllowed(user.getEmail(), providerId)) {
            throw new NewAutoAccountNotAutoEnabledException("New OpenID user, email is not on the domain whitelist.", user);
        }
        if (!_plugin.isEnabled(providerId)) {
            throw new NewAutoAccountNotAutoEnabledException("OpenID provider is not enabled", user);
        }

        log.debug("Checking if user exists...");
        UserI xdatUser;
        String requesterUsername = null;
        try {
            requesterUsername = user.getUsername();
            xdatUser = _userResolver.resolveExisting(requesterUsername, providerId);
        } catch (UsernameAuthMappingNotFoundException e) {
            if (Boolean.parseBoolean(_plugin.getProperty(providerId, "forceUserCreate"))) {
                xdatUser = _userResolver.createUser(providerId, user);
            } else {
                // Give users an option to register or connect OpenID Account with an XNAT account
                log.info("User {} attempted to log using authentication provider ID {}, diverting to account merge page.", user.getUsername(), providerId);
                request.getSession().setAttribute(UsernameAuthMappingNotFoundException.class.getSimpleName(), new UsernameAuthMappingNotFoundException(e.getUsername(), e.getAuthMethod(), e.getAuthMethodId(), user.getEmail(), user.getLastname(), user.getFirstname()));
                response.sendRedirect(TurbineUtils.GetFullServerPath() + "/app/template/RegisterExternalLogin.vm");
                return null;
            }
        }
        if (!xdatUser.isEnabled()) {
            throw new NewAutoAccountNotAutoEnabledException("New OpenID user, needs to to be enabled.", xdatUser);
        }
        if (_accountPolicy.isEmailVerificationRequired(xdatUser)) {
            log.info("User {} is not verified, redirecting to verification page.", xdatUser.getUsername());
            String encodedEmail = URLEncoder.encode(xdatUser.getEmail(), StandardCharsets.UTF_8.toString());
            String encodedUsername = URLEncoder.encode(xdatUser.getUsername(), StandardCharsets.UTF_8.toString());
            response.sendRedirect(TurbineUtils.GetFullServerPath() + "/app/template/VerificationSent.vm" +
                    "?emailTo=" + encodedEmail + "&emailUsername=" + encodedUsername);
            return null;
        }
        if (!xdatUser.isAccountNonLocked()) {
            throw new CredentialsExpiredException("Attempted login to locked account: " + xdatUser.getUsername());
        }

        if (requesterUsername != null) {
            Authentication authentication = new OpenIdAuthToken(xdatUser, providerId, authInfo);

            Authentication authRequestToken = new OpenIdAuthRequestToken(requesterUsername, providerId);
            _eventPublisher.publishAuthenticationSuccess(authRequestToken);

            org.springframework.security.core.context.SecurityContextHolder.getContext().setAuthentication(authRequestToken);
            AccessLogger.LogServiceAccess(xdatUser.getUsername(), request, "Authentication", "SUCCESS");
            UserHelper.setUserHelper(request, user);

            return authentication;
        }
        return null;
    }

    /**
     * Handles unsuccessful authentication attempts.
     * <p>
     * Exception types thrown by attemptAuthentication:
     * - NewAutoAccountNotAutoEnabledException: user not enabled, email domain not whitelisted, or provider disabled
     * - CredentialsExpiredException: account locked (unverified users are redirected directly in attemptAuthentication)
     * - BadCredentialsException: failed to get access token, parse ID token, or invalid username pattern
     * - AuthenticationServiceException: failed to create user account
     */
    @Override
    protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response,
                                              AuthenticationException failed) throws IOException, ServletException {
        // For NewAutoAccountNotAutoEnabledException and CredentialsExpiredException, delegate to the
        // default XNAT failure handler (see XnatUrlAuthenticationFailureHandler)
        if (failed instanceof NewAutoAccountNotAutoEnabledException || failed instanceof CredentialsExpiredException) {
            super.unsuccessfulAuthentication(request, response, failed);
            return;
        }

        // For other errors (BadCredentialsException, etc.), show a user-friendly OIDC-specific message
        String userMessage = getUserMessage(failed);

        // Store the error message in session for the Login screen extension to pick up
        request.getSession().setAttribute(OPENID_ERROR_MESSAGE, userMessage);

        // Redirect to the login page
        response.sendRedirect(TurbineUtils.GetFullServerPath() + "/app/template/Login.vm");
    }

    private static String getUserMessage(final AuthenticationException failed) {
        String userMessage;
        if (failed instanceof BadCredentialsException) {
            String detail = failed.getMessage();
            if (detail != null && detail.contains("usernamePattern")) {
                userMessage = "OpenID Connect login failed due to a configuration error. Please contact your administrator.";
            } else {
                userMessage = "OpenID Connect login failed. Please try again or contact your administrator if the problem persists.";
            }
        } else {
            userMessage = "OpenID Connect login failed. Please try again or contact your administrator if the problem persists.";
        }
        return userMessage;
    }

    private TokenContext parseIdToken(final String idToken, final String providerId)
            throws JOSEException, ParseException, NotFoundException {
        final SignedJWT signedJWT;
        if (isIdTokenEncrypted(idToken)) {
            final EncryptedJWT encryptedJWT = EncryptedJWT.parse(idToken);
            encryptedJWT.decrypt(new RSADecrypter(_keystoreService.getEncryptionPrivateKey(providerId)));

            // The decrypted payload is the inner signed JWT, whose header carries the meaningful typ.
            final String decryptedPayload = encryptedJWT.getPayload().toString();
            signedJWT = SignedJWT.parse(decryptedPayload);
        } else {
            signedJWT = SignedJWT.parse(idToken);
        }
        return new TokenContext(signedJWT.getJWTClaimsSet(), signedJWT.getHeader().toJSONObject());
    }

    private boolean isIdTokenEncrypted(final String idToken) {
        return idToken.split("\\.").length == 5;
    }

    /**
     * Runs the claim-validation gates enabled for the interactive ID-token path against the parsed
     * token claims. A gate failure means the credential is valid but the caller is not authorized;
     * on this path the status code is invisible (the outcome is a login redirect), so it is mapped
     * to {@link BadCredentialsException}, reusing the existing validation-failure handling. With no
     * gates enabled this is a no-op.
     */
    void applyIdTokenClaimGates(final String providerId, final TokenContext token) {
        try {
            for (final ClaimGate gate : _gateFactory.gatesFor(providerId, AuthPath.ID_TOKEN)) {
                gate.check(token);
            }
        } catch (final ClaimGateException e) {
            log.info("OpenID claim gate rejected user for provider '{}': {}", providerId, e.getMessage());
            throw new BadCredentialsException(e.getMessage(), e);
        }
    }


    private Map<String, Object> getUserInfo(final String accessToken, final String userInfoEndpoint) {
        // See https://openid.net/specs/openid-connect-core-1_0.html#UserInfo
        final HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        headers.set(HttpHeaders.AUTHORIZATION, "Bearer " + accessToken);
        final Map<?, ?> body = _restTemplate.exchange(userInfoEndpoint, HttpMethod.GET, new HttpEntity<>(headers), Map.class).getBody();
        return MapUtils.isEmpty(body) ? Collections.emptyMap() : GenericUtils.convertToTypedMap(body, String.class, Object.class);
    }

    private static class NoopAuthenticationManager implements AuthenticationManager {
        @Override
        public Authentication authenticate(Authentication authentication) throws AuthenticationException {
            throw new UnsupportedOperationException("No authentication should be done with this AuthenticationManager");
        }
    }
}

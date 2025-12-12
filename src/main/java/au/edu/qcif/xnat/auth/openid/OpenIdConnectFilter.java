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

import au.edu.qcif.xnat.auth.openid.service.KeystoreService;
import au.edu.qcif.xnat.auth.openid.tokens.OpenIdAuthRequestToken;
import au.edu.qcif.xnat.auth.openid.tokens.OpenIdAuthToken;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.crypto.RSADecrypter;
import com.nimbusds.jwt.EncryptedJWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.collections.ListUtils;
import org.apache.commons.lang3.RegExUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.velocity.VelocityContext;
import org.nrg.framework.generics.GenericUtils;
import org.nrg.xapi.exceptions.NotFoundException;
import org.nrg.xdat.entities.XdatUserAuth;
import org.nrg.xdat.exceptions.UsernameAuthMappingNotFoundException;
import org.nrg.xdat.preferences.SiteConfigPreferences;
import org.nrg.xdat.security.helpers.UserHelper;
import org.nrg.xdat.security.helpers.Users;
import org.nrg.xdat.services.XdatUserAuthService;
import org.nrg.xdat.turbine.utils.AccessLogger;
import org.nrg.xdat.turbine.utils.AdminUtils;
import org.nrg.xdat.turbine.utils.TurbineUtils;
import org.nrg.xft.event.EventDetails;
import org.nrg.xft.event.EventUtils;
import org.nrg.xft.security.UserI;
import org.nrg.xnat.security.exceptions.NewAutoAccountNotAutoEnabledException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.AuthenticationEventPublisher;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationServiceException;
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
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.function.Function;
import java.util.stream.Collectors;

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
    private static final List<String> ALL_DOMAINS = Collections.singletonList("*");
    private static final String PRE_ESTABLISHED_REDIRECT_URI_PROPERTY = "preEstablishedRedirUri";

    /**
     * Session attribute key for storing OpenID error messages to display on the login page.
     */
    public static final String OPENID_ERROR_MESSAGE = "openIdErrorMessage";

    private final OpenIdAuthPlugin _plugin;
    private final AuthenticationEventPublisher _eventPublisher;
    private final XdatUserAuthService _userAuthService;
    private final SiteConfigPreferences _siteConfigPreferences;
    private final Map<String, List<String>> _allowedDomains;
    private final KeystoreService _keystoreService;

    private OAuth2RestTemplate _restTemplate;

    public OpenIdConnectFilter(final OpenIdAuthPlugin plugin,
                               final AuthenticationEventPublisher eventPublisher,
                               final XdatUserAuthService userAuthService,
                               final SiteConfigPreferences siteConfigPreferences,
                               final KeystoreService keystoreService) {
        super(plugin.getProps().getProperty(PRE_ESTABLISHED_REDIRECT_URI_PROPERTY));
        log.debug("Creating filter for URL {}", plugin.getProps().getProperty(PRE_ESTABLISHED_REDIRECT_URI_PROPERTY));
        setAuthenticationManager(new NoopAuthenticationManager());
        _plugin = plugin;
        _eventPublisher = eventPublisher;
        _userAuthService = userAuthService;
        _siteConfigPreferences = siteConfigPreferences;
        _keystoreService = keystoreService;

        _allowedDomains = _plugin.getEnabledProviders().stream().collect(Collectors.toMap(Function.identity(), this::getAllowedEmailDomains));
    }

    @Autowired
    @Override
    public void setAuthenticationSuccessHandler(final AuthenticationSuccessHandler handler) {
        super.setAuthenticationSuccessHandler(handler);
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

        final JWTClaimsSet claimsSet;
        try {
            claimsSet = parseIdToken(idToken, providerId);
        } catch (JOSEException | ParseException e) {
            log.error("An unexpected error occurred attempting to parse id_token", e);
            throw new BadCredentialsException("Failed to parse id_token", e);
        } catch (NotFoundException e) {
            log.error("Provider id {} not configured", providerId, e);
            throw new BadCredentialsException("Provider not configured", e);
        }

        final Map<String, String> authInfo = claimsSet.getClaims().entrySet().stream()
                .collect(Collectors.toMap(
                        Map.Entry::getKey,
                        e -> e.getValue() != null ? e.getValue().toString() : ""
                ));

        log.debug("===== : {}", authInfo);
        final String userInfoUri = _plugin.getProperty(providerId, "userInfoUri");

        if (!StringUtils.isEmpty(userInfoUri)) {
            Map<String, String> userInfo = getUserInfo(accessToken.getValue(), userInfoUri);
            authInfo.putAll(userInfo);
        }

        final OpenIdConnectUserDetails user;
        try {
            user = new OpenIdConnectUserDetails(providerId, authInfo, accessToken, _plugin);
        } catch (IllegalArgumentException e) {
            log.error("OpenID authentication failed for provider '{}'", providerId, e);
            throw new BadCredentialsException(e.getMessage(), e);
        }

        if (shouldFilterEmailDomains(providerId) && !isAllowedEmailDomain(user.getEmail(), providerId)) {
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
            xdatUser = _userAuthService.getUserDetailsByNameAndAuth(requesterUsername, XdatUserAuthService.OPENID, providerId);
        } catch (UsernameAuthMappingNotFoundException e) {
            if (Boolean.parseBoolean(_plugin.getProperty(providerId, "forceUserCreate"))) {
                xdatUser = createUserAccount(providerId, user);
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
        if (getSiteConfigPreferences().getEmailVerification() && !xdatUser.isVerified()) {
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
            Authentication authentication = new OpenIdAuthToken(xdatUser, providerId);

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
     *
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

        // Store the error message in session for the Login screen extension to pick up
        request.getSession().setAttribute(OPENID_ERROR_MESSAGE, userMessage);

        // Redirect to the login page
        response.sendRedirect(TurbineUtils.GetFullServerPath() + "/app/template/Login.vm");
    }

    private JWTClaimsSet parseIdToken(final String idToken, final String providerId)
            throws JOSEException, ParseException, NotFoundException {
        if (isIdTokenEncrypted(idToken)) {
            final EncryptedJWT encryptedJWT = EncryptedJWT.parse(idToken);
            encryptedJWT.decrypt(new RSADecrypter(_keystoreService.getEncryptionPrivateKey(providerId)));

            final String decryptedPayload = encryptedJWT.getPayload().toString();
            return SignedJWT.parse(decryptedPayload).getJWTClaimsSet();
        } else {
            return SignedJWT.parse(idToken).getJWTClaimsSet();
        }
    }

    private boolean isIdTokenEncrypted(final String idToken) {
        return idToken.split("\\.").length == 5;
    }

    private UserI createUserAccount(final String providerId, final OpenIdConnectUserDetails user) throws AuthenticationException {
        // Use standard XNAT provider attributes (auto.enabled/auto.verified) for consistency with other authentication providers
        boolean autoEnabled = _plugin.isAutoEnabled(providerId);
        boolean autoVerified = _plugin.isAutoVerified(providerId);

        UserI xdatUser = Users.createUser();
        xdatUser.setLogin(sanitizeUsername(user.getUsername()));
        xdatUser.setFirstname(user.getFirstname());
        xdatUser.setLastname(user.getLastname());
        xdatUser.setEmail(user.getEmail());
        xdatUser.setEnabled(autoEnabled);
        xdatUser.setVerified(autoVerified);

        log.info("Create user, username: {}", xdatUser.getUsername());
        try {
            UserI adminUser = Users.getAdminUser();
            XdatUserAuth auth = new XdatUserAuth(user.getUsername(), XdatUserAuthService.OPENID, providerId, xdatUser.getLogin(), true, 0);
            Users.save(xdatUser, adminUser, auth,
                    false, new EventDetails(EventUtils.CATEGORY.DATA, EventUtils.TYPE.WEB_SERVICE,
                            "Added User", "Requested by user " + adminUser.getUsername(),
                            "Created new user " + user.getUsername() + " through OpenID connect."));
            xdatUser.setAuthorization(auth);
        } catch (Exception e) {
            log.error("Failed to create user account for OpenID user {}", user.getUsername(), e);
            throw new AuthenticationServiceException("Failed to create user account", e);
        }

        // Send email notifications
        try {
            if (!autoVerified) {
                AdminUtils.sendNewUserVerificationEmail(xdatUser);
            } else {
                AdminUtils.sendNewUserNotification(xdatUser, "", "", "", new VelocityContext());
            }
        } catch (Exception e) {
            log.error("Error sending email notification for user {}", xdatUser.getUsername(), e);
        }

        return xdatUser;
    }

    private boolean shouldFilterEmailDomains(final String providerId) {
        return Boolean.parseBoolean(StringUtils.defaultIfBlank(_plugin.getProperty(providerId, "shouldFilterEmailDomains"), "false"));
    }

    private List<String> getAllowedEmailDomains(final String providerId) {
        return shouldFilterEmailDomains(providerId)
                ? Arrays.stream(_plugin.getProperty(providerId, "allowedEmailDomains").split("\\s*,\\s*"))
                .map(StringUtils::lowerCase)
                .collect(Collectors.toList())
                : ALL_DOMAINS;
    }

    private boolean isAllowedEmailDomain(final String email, final String providerId) {
        if (!_allowedDomains.containsKey(providerId)) {
            return false;
        }
        if (!shouldFilterEmailDomains(providerId)) {
            return true;
        }
        final List<String> allowedDomains = _allowedDomains.get(providerId);
        if (ListUtils.isEqualList(ALL_DOMAINS, allowedDomains)) {
            return true;
        }
        final String[] emailParts = email.split("@");
        final String domain = emailParts.length >= 2 ? emailParts[1] : null;
        if (StringUtils.isBlank(domain)) {
            log.warn("Couldn't parse a domain from the email address {}, returning false", email);
            return false;
        }
        if (allowedDomains.contains(StringUtils.lowerCase(domain))) {
            log.debug("Matched email {} with allowed domain {} for provider {}", email, _allowedDomains, providerId);
            return true;
        }
        log.debug("Email {} did not match any allowed domains for provider {}: {}", email, providerId, StringUtils.join(_allowedDomains, ", "));
        return false;
    }

    protected SiteConfigPreferences getSiteConfigPreferences() {
        return _siteConfigPreferences;
    }

    private Map<String, String> getUserInfo(final String accessToken, final String userInfoEndpoint) {
        // See https://openid.net/specs/openid-connect-core-1_0.html#UserInfo
        final HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        headers.set(HttpHeaders.AUTHORIZATION, "Bearer " + accessToken);
        return GenericUtils.convertToTypedMap(_restTemplate.exchange(userInfoEndpoint, HttpMethod.GET, new HttpEntity<>(headers), Map.class).getBody(), String.class, String.class);
    }

    /**
     * Replace all characters in the submitted username that are not alphanumeric, dash, underscore, apostrophe, or
     * period with an underscore. This is useful for sanitizing usernames that may have been submitted by users
     * that do not comply with the {@link Users#isValidUsername(String) required format}.
     *
     * @param candidate The proposed username to sanitize.
     * @return The sanitized username.
     * @throws IllegalArgumentException If the candidate username can't be sanitized to a valid username, e.g. too long or doesn't start with a letter.
     */
    // TODO: This is here to provide compatibility with older versions of XNAT, but eventually should use XNAT's version of this method.
    private static String sanitizeUsername(final String candidate) {
        final String transformed = RegExUtils.replaceAll(candidate, "[^a-zA-Z0-9-_'.]", "_");
        if (!Users.isValidUsername(transformed)) {
            throw new IllegalArgumentException("The submitted username '" + candidate + "' does not comply with the required format and cannot be sanitized to a valid username.");
        }
        return transformed;
    }

    private static class NoopAuthenticationManager implements AuthenticationManager {
        @Override
        public Authentication authenticate(Authentication authentication) throws AuthenticationException {
            throw new UnsupportedOperationException("No authentication should be done with this AuthenticationManager");
        }
    }
}

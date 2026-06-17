package au.edu.qcif.xnat.auth.openid;

import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.RegExUtils;
import org.apache.velocity.VelocityContext;
import org.nrg.xdat.entities.XdatUserAuth;
import org.nrg.xdat.exceptions.UsernameAuthMappingNotFoundException;
import org.nrg.xdat.security.helpers.Users;
import org.nrg.xdat.services.XdatUserAuthService;
import org.nrg.xdat.turbine.utils.AdminUtils;
import org.nrg.xft.event.EventDetails;
import org.nrg.xft.event.EventUtils;
import org.nrg.xft.security.UserI;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.core.AuthenticationException;

/**
 * Resolves an OpenID identity to an XNAT {@link UserI}: looking up the existing
 * {@code (username, OPENID, providerId)} authentication mapping and, when configured to, creating a
 * new account. Shared by both authentication paths — the interactive {@link OpenIdConnectFilter} and
 * the bearer-token filter — so that both derive the same {@code auth_user} from the same
 * {@code usernamePattern} and therefore resolve to the same XNAT user (a bearer caller maps to the
 * account a prior interactive login created, rather than re-provisioning on every call).
 */
@Slf4j
class OpenIdUserResolver {

    private final OpenIdAuthPlugin _plugin;
    private final XdatUserAuthService _userAuthService;

    OpenIdUserResolver(final OpenIdAuthPlugin plugin, final XdatUserAuthService userAuthService) {
        _plugin = plugin;
        _userAuthService = userAuthService;
    }

    /**
     * @return the existing XNAT user for this OpenID mapping.
     * @throws UsernameAuthMappingNotFoundException if no mapping exists for {@code (username, OPENID, providerId)}.
     */
    UserI resolveExisting(final String username, final String providerId) throws UsernameAuthMappingNotFoundException {
        return _userAuthService.getUserDetailsByNameAndAuth(username, XdatUserAuthService.OPENID, providerId);
    }

    /**
     * Creates a new XNAT account for the OpenID user, using the provider's standard auto-enabled /
     * auto-verified attributes, and registers the OpenID auth mapping.
     */
    UserI createUser(final String providerId, final OpenIdConnectUserDetails user) throws AuthenticationException {
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
            throw new AuthenticationServiceException("The submitted username '" + candidate + "' does not comply with the required format and cannot be sanitized to a valid username.");
        }
        return transformed;
    }
}

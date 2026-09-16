package au.edu.qcif.xnat.auth.openid;

import au.edu.qcif.xnat.auth.openid.gate.AuthPath;
import au.edu.qcif.xnat.auth.openid.gate.GateConfig;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.RegExUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.velocity.VelocityContext;
import org.nrg.xdat.XDAT;
import org.nrg.xdat.entities.XdatUserAuth;
import org.nrg.xdat.exceptions.UsernameAuthMappingNotFoundException;
import org.nrg.xdat.security.helpers.Users;
import org.nrg.xdat.security.user.exceptions.UserNotFoundException;
import org.nrg.xdat.services.XdatUserAuthService;
import org.nrg.xdat.turbine.utils.AdminUtils;
import org.nrg.xft.event.EventDetails;
import org.nrg.xft.event.EventUtils;
import org.nrg.xft.security.UserI;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.core.AuthenticationException;

import java.util.concurrent.Executor;

/**
 * Resolves an OpenID identity to an XNAT {@link UserI}: looking up the existing
 * {@code (username, OPENID, providerId)} authentication mapping and, when configured to, creating a
 * new account. Shared by both authentication paths — the interactive {@link OpenIdConnectFilter} and
 * the bearer-token filter — so that both derive the same {@code auth_user} from the same
 * {@code usernamePattern} and therefore resolve to the same XNAT user (a bearer caller maps to the
 * account a prior interactive login created, rather than re-provisioning on every call).
 *
 * <p>{@link #linkExisting} additionally covers the case of a <em>second</em> provider for people who
 * already have accounts: it attaches a new provider's identity to the XNAT account an existing
 * provider's mapping already points at, instead of provisioning a duplicate.</p>
 */
@Slf4j
public class OpenIdUserResolver {

    private final OpenIdAuthPlugin _plugin;
    private final XdatUserAuthService _userAuthService;
    private final Executor _notifier;

    /**
     * Notifies on the calling thread, which is what {@code createUser} has always done. Retained for
     * callers constructing this directly; the authentication filters use the constructor below.
     */
    public OpenIdUserResolver(final OpenIdAuthPlugin plugin, final XdatUserAuthService userAuthService) {
        this(plugin, userAuthService, Runnable::run);
    }

    /**
     * Sends link notifications through {@code notifier} rather than on the authentication path, so a slow
     * or unreachable mail server cannot add its latency to the request that links.
     *
     * <p>The filters pass XNAT's own {@code asyncTaskExecutor}. An earlier revision used a static
     * single-threaded executor created here, which meant this class owned a thread for the life of the
     * JVM — in a web application that keeps a reference to the deploying classloader, and its queue was
     * unbounded. Taking the container's executor instead means the pool is sized by site preferences and
     * shut down with the context, and nothing here has a lifecycle to manage.</p>
     */
    public OpenIdUserResolver(final OpenIdAuthPlugin plugin, final XdatUserAuthService userAuthService,
                              final Executor notifier) {
        _plugin = plugin;
        _userAuthService = userAuthService;
        _notifier = notifier;
    }

    /**
     * @return the existing XNAT user for this OpenID mapping.
     * @throws UsernameAuthMappingNotFoundException if no mapping exists for {@code (username, OPENID, providerId)}.
     */
    public UserI resolveExisting(final String username, final String providerId) throws UsernameAuthMappingNotFoundException {
        return _userAuthService.getUserDetailsByNameAndAuth(username, XdatUserAuthService.OPENID, providerId);
    }

    /**
     * Links this identity to an account an existing provider already maps, if the provider is configured
     * to do that on this {@link AuthPath}. Shared by both authentication paths so a site configures the
     * behaviour once and gets it consistently wherever people arrive from.
     *
     * <p>Configuration follows the plugin's usual convention: {@code openid.{p}.linkExisting.*} applies to
     * every path, and a path-scoped {@code openid.{p}.bearer.linkExisting.*} or
     * {@code openid.{p}.idToken.linkExisting.*} overrides it — including a path-scoped {@code false} over a
     * shared {@code true}, for a site that wants this on the API path but not the browser one.</p>
     *
     * @return the linked XNAT user, or {@code null} when linking is off, unconfigured, or matched nothing.
     *
     * @throws AuthenticationException if an eligible account was found but the mapping could not be saved.
     */
    public UserI linkExistingIfConfigured(final String providerId, final AuthPath path, final String username)
            throws AuthenticationException {
        final GateConfig config = new GateConfig(_plugin, providerId, path);
        if (!config.enabled("linkExisting")) {
            return null;
        }
        final String sourceProvider = StringUtils.trimToNull(config.value("linkExisting.sourceProvider"));
        if (sourceProvider == null) {
            log.error("Provider '{}' enables linkExisting on the {} path but sets no "
                    + "linkExisting.sourceProvider; no linking will be attempted until it is set.",
                    providerId, path.prefix());
            return null;
        }
        return linkExisting(providerId, username, sourceProvider);
    }

    /**
     * Finds the authentication mapping under {@code sourceProvider} whose {@code auth_user} equals
     * {@code username} — the row naming the XNAT account that this identity would be attached to.
     *
     * <p>{@code username} is this provider's own {@code usernamePattern} output, so the two providers
     * must resolve the same person to the same string for anything to match. That is a configuration
     * requirement, not something this method can verify; see the startup validation in the bearer filter.</p>
     *
     * @return the source mapping, or {@code null} if either argument is blank or no mapping matches.
     */
    XdatUserAuth findLinkSource(final String username, final String sourceProvider) {
        if (StringUtils.isAnyBlank(username, sourceProvider)) {
            return null;
        }
        return _userAuthService.getUserByNameAndAuth(username, XdatUserAuthService.OPENID, sourceProvider);
    }

    /**
     * Looks a mapping up without letting the lookup itself become the failure that is reported. Used only
     * to work out whether a create that failed lost a race, where the original cause is the useful one.
     */
    private XdatUserAuth findLinkSourceQuietly(final String username, final String providerId) {
        try {
            return findLinkSource(username, providerId);
        } catch (Exception e) {
            log.debug("Could not re-read the mapping for '{}' on provider '{}' after a failed create.",
                      username, providerId, e);
            return null;
        }
    }

    /**
     * Attaches {@code username} under {@code providerId} to the XNAT account that
     * {@code sourceProvider}'s mapping for the same {@code username} already points at, so one person
     * keeps one XNAT account across two identity providers.
     *
     * <p>Because both providers key on the same value, the row written here carries the same
     * {@code auth_user} as the source row — every provider ends up keying this person identically,
     * which is what lets a third provider be added later by matching against either.</p>
     *
     * <p>Fails closed and returns {@code null} — leaving the caller to deny the request — when there is
     * no source mapping, when it names no XNAT account, or when that account cannot be loaded.</p>
     *
     * <p>What this does not do is prove that the person owns the XNAT account. The interactive equivalent
     * ({@code RegisterExternalLogin}) requires its password; this trusts that the provider asserted the
     * identity truthfully, so it is exactly as trustworthy as that provider and no more. There is
     * deliberately no carve-out for privileged accounts: a mapping mis-targeted by configuration lands on
     * the wrong person's account whatever roles that account holds, so screening one tier would narrow
     * nothing while implying a protection that is not there. The controls that do the work are that this
     * is off by default, that {@code warnIfLinkExistingCannotMatch} warns at startup about configurations which cannot
     * match, and — decisively — whether the provider presenting the token is trusted to assert who
     * someone is at all.</p>
     *
     * @return the linked XNAT user, or {@code null} if no eligible account could be linked.
     *
     * @throws AuthenticationException if an eligible account was found but the mapping could not be saved.
     */
    public UserI linkExisting(final String providerId, final String username, final String sourceProvider)
            throws AuthenticationException {
        final XdatUserAuth source = findLinkSource(username, sourceProvider);
        if (source == null) {
            log.info("No '{}' mapping is keyed on '{}', so provider '{}' has nothing to link to.",
                     sourceProvider, username, providerId);
            return null;
        }
        final String xdatUsername = source.getXdatUsername();
        if (StringUtils.isBlank(xdatUsername)) {
            log.warn("The '{}' mapping keyed on '{}' names no XNAT account; not linking.", sourceProvider, username);
            return null;
        }

        final UserI existing;
        try {
            existing = Users.getUser(xdatUsername);
        } catch (Exception e) {
            log.warn("The '{}' mapping names XNAT account '{}', which could not be loaded; not linking.",
                     sourceProvider, xdatUsername, e);
            return null;
        }
        XdatUserAuth link = new XdatUserAuth(username, XdatUserAuthService.OPENID, providerId);
        link.setXdatUsername(xdatUsername);
        boolean created = false;
        try {
            _userAuthService.create(link);
            created = true;
            log.info("Linked '{}' on provider '{}' to existing XNAT account '{}' (matched the '{}' mapping).",
                     username, providerId, xdatUsername, sourceProvider);
        } catch (Exception e) {
            // A concurrent request for the same person may have created the mapping first: linking runs on
            // a lookup miss, and a viewer opening a study issues several requests at once, so the first
            // few can all miss and all try to create it. Re-read before failing — if the mapping is now
            // there and names the same account, that request won and this one can go on to use it.
            final XdatUserAuth raced = findLinkSourceQuietly(username, providerId);
            if (raced == null || !StringUtils.equals(xdatUsername, raced.getXdatUsername())) {
                log.error("Failed to link '{}' on provider '{}' to XNAT account '{}'", username, providerId, xdatUsername, e);
                throw new AuthenticationServiceException("Failed to link the OpenID identity to an existing XNAT account", e);
            }
            log.info("Mapping for '{}' on provider '{}' was created concurrently; using it.", username, providerId);
            link = raced;
        }
        // Only the request that created the mapping announces it. Every loser of the race reaches the
        // same account by the same link, so notifying from here would send one message per concurrent
        // request -- and concurrent first requests are the normal case, not the exception.
        if (created) {
            notifyOfLink(existing, providerId, username);
        }
        existing.setAuthorization(link);
        return existing;
    }

    /**
     * Tells the account holder, and the site administrator, that a new identity provider was attached to
     * an existing account.
     *
     * <p>Account creation already notifies (see {@link #createUser}); linking did not, which left it the
     * one thing in this flow that happened silently. That matters most on the interactive path, where
     * linking runs <em>instead of</em> XNAT's account-merge page — so where the person would previously
     * have been asked to confirm, they now need to be told after the fact. Telling them is what makes an
     * unexpected link something they can report rather than something nobody sees.</p>
     *
     * <p>Notification failures are logged and swallowed: a link that succeeded must not become a failed
     * login because the mail server was unreachable.</p>
     */
    private void notifyOfLink(final UserI account, final String providerId, final String username) {
        // Everything, including composing the message, happens off the authentication path and inside the
        // guard: a slow or unreachable mail server would otherwise add its latency to the one request that
        // links, and anything that throws while preparing the mail would fail a sign-in that had succeeded.
        _notifier.execute(() -> {
            try {
                final String subject = "New sign-in method added to your account";
                final String body = "The identity '" + username + "' from authentication provider '" + providerId
                        + "' was linked to your XNAT account '" + account.getUsername() + "', so it can now be "
                        + "used to sign in or reach the API as you. If you did not expect this, contact your "
                        + "site administrator.";
                AdminUtils.sendAdminEmail(account, subject, body);
                final String recipient = account.getEmail();
                if (StringUtils.isNotBlank(recipient)) {
                    XDAT.getMailService().sendHtmlMessage(XDAT.getSiteConfigPreferences().getAdminEmail(),
                                                         recipient, subject, body);
                }
            } catch (Exception e) {
                // Only the plain arguments here: the account object is what may have failed, so reporting
                // through it risks throwing from the handler itself.
                log.error("Linked '{}' on provider '{}', but could not send notification of it",
                          username, providerId, e);
            }
        });
    }

    /**
     * Creates a new XNAT account for the OpenID user, using the provider's standard auto-enabled /
     * auto-verified attributes, and registers the OpenID auth mapping.
     */
    public UserI createUser(final String providerId, final OpenIdConnectUserDetails user) throws AuthenticationException {
        final String login = sanitizeUsername(user.getUsername());
        requireLoginIsFree(login, providerId);

        // Use standard XNAT provider attributes (auto.enabled/auto.verified) for consistency with other authentication providers
        boolean autoEnabled = _plugin.isAutoEnabled(providerId);
        boolean autoVerified = _plugin.isAutoVerified(providerId);

        UserI xdatUser = Users.createUser();
        xdatUser.setLogin(login);
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
     * Refuses to run account creation against a login that already belongs to somebody, because
     * {@code Users.save} cannot do it safely and would not say so.
     *
     * <p>Its {@code save(user, …, newUserAuth)} registers the mapping only on its new-account branch
     * ({@code XDATUserMgmtServiceImpl:244}); reached with an existing login it takes the update branch,
     * drops the mapping without error, and writes this freshly-built object over the real account —
     * overwriting its name and email, and resetting {@code enabled} and {@code verified} from
     * <em>this</em> provider's {@code auto.*} settings. Silently re-enabling a deliberately disabled
     * account is the serious one: {@code isEnabled()} is checked on every request and is the only
     * revocation that acts faster than a token's lifetime.</p>
     *
     * <p>So this fails loudly instead, and does not guess. Two providers deriving one login is a
     * legitimate configuration — it is what {@code linkExisting} is for — but attaching to an account on
     * a bare login match alone would take over whatever account happens to hold that name, whichever
     * provider or authentication method created it. {@code linkExisting} requires a named
     * {@code sourceProvider} precisely so that stays a decision rather than a coincidence.</p>
     *
     * @throws AuthenticationException if an XNAT account already holds this login.
     */
    private void requireLoginIsFree(final String login, final String providerId) throws AuthenticationException {
        final boolean taken;
        try {
            // The same idiom XNAT's own save uses to test for an existing account.
            taken = Users.getUser(login) != null;
        } catch (final UserNotFoundException absent) {
            return; // No account holds this login; creation may proceed.
        } catch (final Exception e) {
            // Anything else means we could not determine whether the login is free. Treating that as
            // free would walk straight into the overwrite this guard exists to prevent, so refuse.
            log.error("Could not determine whether XNAT login '{}' is already taken, so provider '{}' will not "
                            + "create an account for it. Refusing rather than risking an overwrite.",
                    login, providerId, e);
            throw new AuthenticationServiceException(
                    "Could not determine whether the login this identity resolves to is already in use");
        }
        if (taken) {
            log.error("Provider '{}' resolved to XNAT login '{}', which already exists but has no mapping for "
                            + "this provider. Refusing to create an account: doing so would overwrite the existing "
                            + "one and lose the mapping. Configure linkExisting.sourceProvider for '{}' to attach to "
                            + "it deliberately, or change its usernamePattern so it stops colliding.",
                    providerId, login, providerId);
            throw new AuthenticationServiceException(
                    "An XNAT account already uses the login this identity resolves to, and no mapping links them");
        }
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

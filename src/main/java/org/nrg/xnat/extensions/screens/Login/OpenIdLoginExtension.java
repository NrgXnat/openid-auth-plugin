package org.nrg.xnat.extensions.screens.Login;

import static au.edu.qcif.xnat.auth.openid.OpenIdConnectFilter.AUTO_LOGIN_ATTEMPTED_COOKIE;
import static au.edu.qcif.xnat.auth.openid.OpenIdConnectFilter.OPENID_ERROR_MESSAGE;

import au.edu.qcif.xnat.auth.openid.OpenIdAuthPlugin;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.apache.turbine.util.RunData;
import org.nrg.framework.utilities.Reflection;
import org.nrg.xdat.XDAT;
import org.nrg.xdat.turbine.utils.TurbineUtils;
import org.nrg.xft.security.UserI;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Map;

/**
 * Login screen extension for the OpenID plugin. This extension is automatically loaded by XNAT's dynamic
 * variable loading mechanism when classes implementing {@link Reflection.InjectableI} are found in the
 * {@code org.nrg.xnat.extensions.screens.Login} package, and runs while the {@code Login.vm} screen is being
 * built (before the response is committed).
 *
 * <p>It does two things:</p>
 * <ol>
 *     <li>Displays a pending OpenID authentication error message on the login page, if there is one.</li>
 *     <li>Otherwise, when a provider opts into it ({@code openid.<providerId>.autoLogin=true}), automatically
 *     redirects an unauthenticated visitor into the OpenID flow with {@code prompt=none}. If the user already
 *     has a session at the provider they are logged straight in; if not, the provider returns an error and the
 *     filter brings them back to this page — which then renders normally.</li>
 * </ol>
 */
@Slf4j
public class OpenIdLoginExtension implements Reflection.InjectableI {

    /**
     * Lifetime of the one-shot auto-login guard cookie, in seconds. Long enough to break the
     * {@code Login.vm -> provider -> callback -> Login.vm} redirect chain, short enough that a later visit
     * retries — so a visitor who signs in at the provider in the meantime is still picked up automatically.
     */
    private static final int AUTO_LOGIN_COOKIE_MAX_AGE_SECONDS = 120;

    @Override
    public void execute(Map<String, Object> params) {
        final RunData data = (RunData) params.get("data");
        if (data == null) {
            return;
        }
        try {
            handle(data, resolveCurrentUser(), resolvePlugin());
        } catch (Exception e) {
            // Never let a problem here break login-page rendering.
            log.error("Error processing OpenID login extension", e);
        }
    }

    /** The current request's user; isolated here so tests can override it without the static XNAT dependency. */
    UserI resolveCurrentUser() {
        return XDAT.getUserDetails();
    }

    /** The OpenID plugin bean; isolated here so tests can override it without the static XNAT dependency. */
    OpenIdAuthPlugin resolvePlugin() {
        return XDAT.getContextService().getBeanSafely(OpenIdAuthPlugin.class);
    }

    /**
     * Core logic, split out from {@link #execute} so it can be unit-tested without the static XNAT lookups.
     *
     * @param data        the Turbine request data for the login page.
     * @param currentUser the current user (guest/anonymous if not logged in), or {@code null} if unknown.
     * @param plugin      the OpenID plugin, or {@code null} if it could not be resolved.
     */
    void handle(final RunData data, final UserI currentUser, final OpenIdAuthPlugin plugin) throws IOException {
        final HttpSession session = data.getSession();

        // A pending error message means a previous login attempt failed; show it and let the user decide,
        // rather than redirecting and potentially masking the problem.
        final String errorMessage = (String) session.getAttribute(OPENID_ERROR_MESSAGE);
        if (StringUtils.isNotBlank(errorMessage)) {
            log.debug("Setting OpenID error message on login page: {}", errorMessage);
            data.setMessage(errorMessage);
            // Remove the attribute so it doesn't persist across page loads.
            session.removeAttribute(OPENID_ERROR_MESSAGE);
            return;
        }

        maybeAutoLogin(data, currentUser, plugin);
    }

    private void maybeAutoLogin(final RunData data, final UserI currentUser, final OpenIdAuthPlugin plugin)
            throws IOException {
        final HttpServletResponse response = data.getResponse();
        // The Login screen redirects an already-authenticated user to the dashboard and commits the response
        // before this runs; never attempt a second redirect.
        if (response == null || response.isCommitted()) {
            return;
        }
        // Only anonymous (guest) visitors should be auto-redirected.
        if (currentUser != null && !currentUser.isGuest()) {
            return;
        }
        // One-shot guard: a short-lived cookie set when the last auto-login was issued. It is a cookie rather
        // than a session attribute because it must survive the Login.vm -> /openid-login -> provider ->
        // callback redirect chain, across which the HttpSession does not reliably persist.
        if (hasAutoLoginAttemptCookie(data)) {
            return;
        }
        final String providerId = plugin == null ? null : plugin.getAutoLoginProviderId();
        if (StringUtils.isBlank(providerId)) {
            return;
        }

        setAutoLoginAttemptCookie(data);
        final String target = fullServerPath() + "/openid-login?providerId="
                + URLEncoder.encode(providerId, StandardCharsets.UTF_8.name()) + "&prompt=none";
        log.debug("Attempting OpenID auto-login via provider '{}'", providerId);
        response.sendRedirect(target);
    }

    /** True if the one-shot auto-login guard cookie is present on the request. */
    private static boolean hasAutoLoginAttemptCookie(final RunData data) {
        return hasNamedCookie(data, AUTO_LOGIN_ATTEMPTED_COOKIE);
    }

    private static boolean hasNamedCookie(final RunData data, final String name) {
        final HttpServletRequest request = data.getRequest();
        if (request == null || request.getCookies() == null) {
            return false;
        }
        for (final Cookie cookie : request.getCookies()) {
            if (name.equals(cookie.getName())) {
                return true;
            }
        }
        return false;
    }

    /** Sets the short-lived, one-shot guard cookie marking that an auto-login has just been attempted. */
    private void setAutoLoginAttemptCookie(final RunData data) {
        final HttpServletRequest request = data.getRequest();
        final Cookie cookie = new Cookie(AUTO_LOGIN_ATTEMPTED_COOKIE, "1");
        cookie.setPath("/");
        cookie.setHttpOnly(true);
        cookie.setSecure(request != null && request.isSecure());
        cookie.setMaxAge(AUTO_LOGIN_COOKIE_MAX_AGE_SECONDS);
        data.getResponse().addCookie(cookie);
    }

    /** The site's full server path; isolated here so tests can override it without the static XNAT dependency. */
    String fullServerPath() {
        return TurbineUtils.GetFullServerPath();
    }
}

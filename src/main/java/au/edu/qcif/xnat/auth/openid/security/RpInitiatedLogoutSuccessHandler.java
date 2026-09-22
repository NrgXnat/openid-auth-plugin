package au.edu.qcif.xnat.auth.openid.security;

import lombok.extern.slf4j.Slf4j;
import org.nrg.xdat.turbine.utils.TurbineUtils;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;

/**
 * RP-initiated (single) logout per OpenID Connect RP-Initiated Logout 1.0: after XNAT's local logout, redirect
 * the browser to the provider's end-session endpoint so the shared provider (SSO) session is ended too, then
 * back to the XNAT login page. Installed only when the auto-login provider configures {@code logoutUri}.
 *
 * <p>Sends {@code id_token_hint} (captured by {@link OpenIdLogoutHandler} before the session was invalidated)
 * when available, plus {@code client_id} and {@code post_logout_redirect_uri}. On an idle timeout the id_token
 * is already gone, so the request is a best-effort logout without the hint: a proxy-style {@code logoutUri}
 * (e.g. oauth2-proxy sign-out) logs out anyway, while a provider end-session endpoint that requires the hint
 * (e.g. Keycloak) will prompt the user to confirm. The provider must permit the post-logout redirect URI, so
 * register the XNAT login URL as an allowed post-logout redirect on the client.</p>
 */
@Slf4j
public class RpInitiatedLogoutSuccessHandler implements LogoutSuccessHandler {

    private final String endSessionUri;
    private final String clientId;

    public RpInitiatedLogoutSuccessHandler(final String endSessionUri, final String clientId) {
        this.endSessionUri = endSessionUri;
        this.clientId = clientId;
    }

    @Override
    public void onLogoutSuccess(final HttpServletRequest request, final HttpServletResponse response,
                                final Authentication authentication) throws IOException {
        final Object idTokenHint = request.getAttribute(OpenIdLogoutHandler.ID_TOKEN_HINT_ATTRIBUTE);
        final String postLogoutRedirectUri = fullServerPath() + "/app/template/Login.vm";
        log.debug("RP-initiated logout: redirecting to provider end-session endpoint");
        response.sendRedirect(buildEndSessionUrl(postLogoutRedirectUri, idTokenHint == null ? null : idTokenHint.toString()));
    }

    /** Builds the end-session URL with id_token_hint (when available), the post-logout redirect, and client_id. */
    String buildEndSessionUrl(final String postLogoutRedirectUri, final String idTokenHint) throws IOException {
        final StringBuilder url = new StringBuilder(endSessionUri).append(endSessionUri.contains("?") ? '&' : '?');
        if (idTokenHint != null && !idTokenHint.isEmpty()) {
            url.append("id_token_hint=").append(enc(idTokenHint)).append('&');
        }
        url.append("post_logout_redirect_uri=").append(enc(postLogoutRedirectUri));
        if (clientId != null && !clientId.isEmpty()) {
            url.append("&client_id=").append(enc(clientId));
        }
        return url.toString();
    }

    /** The site's full server path; isolated here so tests can override it without the static XNAT dependency. */
    String fullServerPath() {
        return TurbineUtils.GetFullServerPath();
    }

    private static String enc(final String value) throws IOException {
        return URLEncoder.encode(value, StandardCharsets.UTF_8.name());
    }
}

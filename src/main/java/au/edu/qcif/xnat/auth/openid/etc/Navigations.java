package au.edu.qcif.xnat.auth.openid.etc;

import org.apache.commons.lang3.StringUtils;

import javax.servlet.http.HttpServletRequest;

/**
 * Tells a browser's top-level page load apart from a request a page script makes (XHR, {@code fetch}), which can't
 * follow a sign-in redirect to the provider.
 */
public final class Navigations {

    private Navigations() {
    }

    /**
     * True for a page load, top-level or in a frame. Browsers send {@code Sec-Fetch-*}, which scripts can't set; without
     * it, a request for HTML counts unless it carries {@code X-Requested-With}, since some of XNAT's XHRs ask for HTML
     * too. A frame counts because auto-login asks with {@code prompt=none}, which never shows the provider's own page:
     * the provider answers with a redirect back, and one that can't sign the user in that way returns them to the login
     * page.
     */
    public static boolean isNavigation(final HttpServletRequest request) {
        final String mode = request.getHeader("Sec-Fetch-Mode");
        if (mode != null) {
            final String dest = request.getHeader("Sec-Fetch-Dest");
            return "navigate".equals(mode)
                    && (dest == null || "document".equals(dest) || "iframe".equals(dest) || "frame".equals(dest));
        }
        return StringUtils.contains(request.getHeader("Accept"), "text/html") && request.getHeader("X-Requested-With") == null;
    }
}

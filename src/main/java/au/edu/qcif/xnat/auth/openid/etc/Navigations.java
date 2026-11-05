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
     * True for a top-level page load. Browsers send {@code Sec-Fetch-*}, which scripts can't set; without it, a request
     * for HTML counts unless it carries {@code X-Requested-With}, since some of XNAT's XHRs ask for HTML too.
     */
    public static boolean isNavigation(final HttpServletRequest request) {
        final String mode = request.getHeader("Sec-Fetch-Mode");
        if (mode != null) {
            final String dest = request.getHeader("Sec-Fetch-Dest");
            return "navigate".equals(mode) && (dest == null || "document".equals(dest));
        }
        return StringUtils.contains(request.getHeader("Accept"), "text/html") && request.getHeader("X-Requested-With") == null;
    }
}

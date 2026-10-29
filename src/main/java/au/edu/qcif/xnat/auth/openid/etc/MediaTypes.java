package au.edu.qcif.xnat.auth.openid.etc;

import org.apache.commons.lang3.StringUtils;

/**
 * RFC 7515 treats a JOSE header {@code typ} of {@code X} and {@code application/X} as equivalent.
 */
public final class MediaTypes {

    private static final String APPLICATION_PREFIX = "application/";

    private MediaTypes() {
    }

    public static String withoutApplicationPrefix(final String typ) {
        final String subtype = StringUtils.removeStart(typ, APPLICATION_PREFIX);
        return subtype.contains("/") ? typ : subtype;
    }

    public static String withApplicationPrefix(final String subtype) {
        return APPLICATION_PREFIX + subtype;
    }
}

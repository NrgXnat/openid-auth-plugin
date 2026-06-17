package au.edu.qcif.xnat.auth.openid.gate;

/**
 * The two independent authentication paths the gates can run on, each with its own per-path enable
 * toggles and optional per-path config overrides. The {@link #prefix()} is the configuration
 * namespace for that path, e.g. {@code openid.{providerId}.idToken.roleCheck.enabled}.
 */
public enum AuthPath {

    /** The interactive ID-token path handled by {@code OpenIdConnectFilter}. */
    ID_TOKEN("idToken"),

    /** The bearer-token path (filter to be added). */
    BEARER("bearer");

    private final String prefix;

    AuthPath(final String prefix) {
        this.prefix = prefix;
    }

    /** The configuration namespace segment for this path. */
    public String prefix() {
        return prefix;
    }
}

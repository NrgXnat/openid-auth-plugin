package au.edu.qcif.xnat.auth.openid.etc;

public class OpenIdAuthConstant {
    public static final String PKCE_ENABLED      = "pkceEnabled";
    public static final String EMAIL             = "emailProperty";
    public static final String GIVEN_NAME        = "givenNameProperty";
    public static final String FAMILY_NAME       = "familyNameProperty";
    public static final String USERNAME_PATTERN  = "usernamePattern";
    public static final String KEY_REDIR_URI     = "preEstablishedRedirUri";
    public static final String DEFAULT_REDIR_URI = "/openid-login";
    public static final String PROVIDER_ID       = "providerId";
    public static final String ID_TOKEN          = "id_token";
    public static final String ACCESS_TOKEN      = "access_token";
    public static final byte[] CHUNK_SEPARATOR   = {'\r', '\n'};
}

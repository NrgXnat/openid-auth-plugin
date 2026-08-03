package au.edu.qcif.xnat.auth.openid.tokens;

import org.nrg.xnat.security.tokens.AbstractXnatAuthenticationToken;

/**
 * Plugin's XNAT Auth Request token
 */
public class OpenIdAuthRequestToken extends AbstractXnatAuthenticationToken {
	public OpenIdAuthRequestToken(final String username, final String providerId) {
		super(providerId, username, null);
	}

	public String toString() {
		return getPrincipal() + ": " + getProviderId();
	}

}

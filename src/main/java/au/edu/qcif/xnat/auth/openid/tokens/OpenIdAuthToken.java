package au.edu.qcif.xnat.auth.openid.tokens;

import org.nrg.xft.security.UserI;
import org.nrg.xnat.security.tokens.AbstractXnatAuthenticationToken;
import org.springframework.security.core.SpringSecurityCoreVersion;

import javax.annotation.Nullable;
import java.util.Map;

/**
 * Plugin's XNAT Auth token
 * 
 * @author <a href="https://github.com/shilob">Shilo Banihit</a>
 * 
 */
public class OpenIdAuthToken extends AbstractXnatAuthenticationToken {

	private static final long serialVersionUID = SpringSecurityCoreVersion.SERIAL_VERSION_UID;
	private final Map<String, Object> openIdUserInfo;


	public OpenIdAuthToken(final UserI details, final String providerId, final Map<String, Object> openIdUserInfo) {
		super(providerId, details, null, details.getAuthorities());
		this.openIdUserInfo = openIdUserInfo;
	}

	@Nullable
	public Map<String, Object> getOpenIdUserInfo() {
		return openIdUserInfo;
	}

	public String toString() {
		return getPrincipal() + ": " + getProviderId();
	}

}



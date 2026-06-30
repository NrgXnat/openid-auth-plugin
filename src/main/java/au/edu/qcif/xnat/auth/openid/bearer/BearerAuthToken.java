package au.edu.qcif.xnat.auth.openid.bearer;

import au.edu.qcif.xnat.auth.openid.tokens.OpenIdAuthToken;
import org.nrg.xft.security.UserI;
import org.springframework.security.core.Transient;

/**
 * Authentication token for the bearer-token REST path. Identical to {@link OpenIdAuthToken} except
 * that it is marked {@link Transient}: Spring Security's {@code HttpSessionSecurityContextRepository}
 * checks for this annotation in {@code saveContext} and skips persisting the {@code SecurityContext}
 * to an {@code HttpSession}, so no {@code JSESSIONID} is created for a bearer request.
 *
 * <p>The interactive ID-token flow keeps using the non-transient {@link OpenIdAuthToken}, which is
 * persisted to a session as a browser login should be.</p>
 */
@Transient
public class BearerAuthToken extends OpenIdAuthToken {

	public BearerAuthToken(final UserI details, final String providerId) {
		super(details, providerId);
	}
}

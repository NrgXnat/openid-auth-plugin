/*
 *Copyright (C) 2018 Queensland Cyber Infrastructure Foundation (http://www.qcif.edu.au/)
 *
 *This program is free software: you can redistribute it and/or modify
 *it under the terms of the GNU General Public License as published by
 *the Free Software Foundation; either version 2 of the License, or
 *(at your option) any later version.
 *
 *This program is distributed in the hope that it will be useful,
 *but WITHOUT ANY WARRANTY; without even the implied warranty of
 *MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *GNU General Public License for more details.
 *
 *You should have received a copy of the GNU General Public License along
 *with this program; if not, write to the Free Software Foundation, Inc.,
 *51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */
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

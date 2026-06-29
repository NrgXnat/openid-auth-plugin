# XNAT OpenID Authentication Plugin Changelog

Adds OpenID Connect (OIDC) authentication support to XNAT.

## <a name="1.6.0"></a>OpenID Authentication Plugin Version 1.6.x Release Notes

### <a name="1.6.0"></a>Version 1.6.0

#### 1.6.0 - New Features
* Added optional, configurable claim-validation gates for token authorization:
    * **Audience (`aud`) gate** — rejects a token whose audience does not contain one of the configured accepted audiences (`openid.<providerId>.audCheck.acceptedAudiences`).
    * **Role gate** — rejects a token that carries none of the configured required roles (any-of), read from a configurable nested claim path such as `resource_access.<client>.roles` (`openid.<providerId>.roleCheck.rolePath` and `roleCheck.requiredRoles`).
    * Both gates are opt-in (default off). Every gate property — including the enable toggles — can be set once per provider (e.g. `openid.<providerId>.audCheck.enabled`) to apply to all paths, or scoped to a single path (e.g. `openid.<providerId>.idToken.audCheck.enabled`, `openid.<providerId>.bearer.roleCheck.rolePath`), where the path-scoped value overrides the shared one. Wired into the interactive ID-token path; the path-agnostic gate infrastructure is ready for the upcoming bearer-token path. See the README for full configuration details.


## <a name="1.5.0"></a>OpenID Authentication Plugin Version 1.5.x Release Notes
**BREAKING CHANGE:** 1.5.0 is compiled in Java21 and has dependency updates that require XNAT 1.10.0. 

### <a name="1.5.0"></a>Version 1.5.0

#### 1.5.0 - Fixes
* [PLUGINS-274](https://radiologics.atlassian.net/browse/PLUGINS-274) Enable usage of longer keys via custom-state generator 
* [PLUGINS-293](https://radiologics.atlassian.net/browse/PLUGINS-293) Fix startup failure when no OpenID providers are specified 


## <a name="1.4.0"></a>OpenID Authentication Plugin Version 1.4.x Release Notes
**BREAKING CHANGE:** 1.4.0 removes duplicative properties `userAutoEnabled` and `userAutoVerified`. Before installing 1.4.0, make sure you have set `auto.enabled` and `auto.verified` appropriately. 
If you have `forceUserCreate=true`, you might need to change them to match the values in `userAutoEnabled` and `userAutoVerified`. If you have `forceUserCreate=false`, you probably already needed to set
`auto.enabled` and `auto.verified` per your desired configuration.

### <a name="1.4.1"></a>Version: 1.4.1

#### 1.4.1 - Fixes
* [PLUGINS-265](https://radiologics.atlassian.net/browse/PLUGINS-265)
    * Fixed issue where newly created users were locked out on first login if `auto.enabled: true`
    * Exceptions during user creation are no longer swallowed
* [PLUGINS-263](https://radiologics.atlassian.net/browse/PLUGINS-263)
    * Improved logging and error handling for invalid `usernamePattern` configuration
    * OIDC authentication errors now take users to the login page with an OIDC-specific error message instead of a stuck "Refreshing data type cache" modal
* [PLUGINS-266](https://radiologics.atlassian.net/browse/PLUGINS-266) Fixed issue where newly created users got a confusing message and no verification email on first login when `auto.verified: false`

### <a name="1.4.0"></a>Version: 1.4.0

#### 1.4.0 - New Features
* [PLUGINS-221](https://radiologics.atlassian.net/browse/PLUGINS-221) Added support for encrypted ID tokens
	* Added API endpoints
		* Privacy Policy: `/xapi/openid/legal/privacy-policy`
		* Terms of Service: `/xapi/openid/legal/terms-of-service`
		* JWKS: `/xapi/openid/.well-known/jwks.json`
	* Caveats:
		* Only RSA-based encryption algorithms are supported
* [PLUGINS-249](https://radiologics.atlassian.net/browse/PLUGINS-249) ID token encryption works in multi-node deployments

#### 1.4.0 - General Improvements
* [PLUGINS-216](https://radiologics.atlassian.net/browse/PLUGINS-216) Added username sanitization when auto-creating user accounts for new XNAT users
* [PLUGINS-251](https://radiologics.atlassian.net/browse/PLUGINS-251) Removed duplicative properties `userAutoEnabled` and `userAutoVerified` in favor of `auto.enabled` and `auto.verified`, which are expected from all authentication providers in XNAT

#### 1.4.0 - Fixes
* [PLUGINS-250](https://radiologics.atlassian.net/browse/PLUGINS-250) Fixed UX issue where setting `forceUserCreate=true` but `userAutoEnabled=false` sent the user to `InactiveAccount.vm` and did not send new user notification email 
* [PLUGINS-188](https://radiologics.atlassian.net/browse/PLUGINS-188) Fixed unit test error caused by mismatched provider ID

## Note

Versions prior to 1.4.0 were not tracked with this changelog. You will need to visit JIRA or the Bitbucket commit history for details.
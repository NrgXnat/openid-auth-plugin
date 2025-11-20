# XNAT OpenID Authentication Plugin

Adds OpenID Connect (OIDC) authentication support to XNAT.

## <a name="1.4.0"></a>OpenID Authentication Plugin Version 1.4.0 Release Notes
**BREAKING CHANGE:** 1.4.0 removes duplicative properties `userAutoEnabled` and `userAutoVerified`. Before installing 1.4.0, make sure you have set `auto.enabled` and `auto.verified` appropriately. 
If you have `forceUserCreate=true`, you might need to change them to match the values in `userAutoEnabled` and `userAutoVerified`. If you have `forceUserCreate=false`, you probably already needed to set
`auto.enabled` and `auto.verified` per your desired configuration.

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

#### 1.4.0 - Bug Fixes
* [PLUGINS-250](https://radiologics.atlassian.net/browse/PLUGINS-250) Fixed UX issue where setting `forceUserCreate=true` but `userAutoEnabled=false` sent the user to `InactiveAccount.vm` and did not send new user notification email 
* [PLUGINS-188](https://radiologics.atlassian.net/browse/PLUGINS-188) Fixed unit test error caused by mismatched provider ID

## Note

Versions prior to 1.4.0 were not tracked with this changelog. You will need to visit JIRA or the Bitbucket commit history for details.
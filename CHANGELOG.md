# XNAT OpenID Authentication Plugin

Adds OpenID Connect (OIDC) authentication support to XNAT.

## <a name="1.4.0"></a>OpenID Authentication Plugin Version 1.4.0 Release Notes

### <a name="1.4.0"></a>Version: 1.4.0

#### 1.4.0  - New Features
* [PLUGINS-221](https://radiologics.atlassian.net/browse/PLUGINS-221) Added support for encrypted ID tokens
	* Added API endpoints
		* Privacy Policy: `/xapi/openid/legal/privacy-policy`
		* Terms of Service: `/xapi/openid/legal/terms-of-service`
		* JWKS: `/xapi/openid/.well-known/jwks.json`
	* Caveats: 
		* Only RSA-based encryption algorithms are supported
		* Keys are in-memory only and regenerated on each Tomcat restart
		* In load-balanced environments, each node has its own key pair; tokens encrypted with one node’s public key can’t be decrypted by any other node

#### 1.4.0 - General Improvements
* [PLUGINS-216](https://radiologics.atlassian.net/browse/PLUGINS-216) Added username sanitization when auto-creating user accounts for new XNAT users
# XNAT OpenID Connect Authentication Provider Plugin

## Pre-requisities

This plugin is for use with XNAT 1.7.5.x+ releases.

There are 2 ways to deploy XNAT-Web:

## Deploying this plugin

When you have deployed the specific version of XNAT Web, you will need to deploy this XNAT plugin. For more information, please [XNAT documentation on how to deploy plugins.](https://wiki.xnat.org/documentation/xnat-administration/deploying-plugins-in-xnat)

Again there are 2 ways to accomplish this:

### 1. Download the pre-built JAR

Jars are published to XNAT's Artifactory under the coordinates `au.edu.qcif.xnat.openid:openid-auth-plugin`.
The deployable plugin jar is the one with the `xpl` classifier — it bundles the dependencies the plugin
needs at runtime.

1. Pick a version and download the `-xpl` jar:

    * Releases: [`libs-release/au/edu/qcif/xnat/openid/openid-auth-plugin`](https://nrgxnat.jfrog.io/nrgxnat/libs-release/au/edu/qcif/xnat/openid/openid-auth-plugin/)
    * Snapshots: [`libs-snapshot/au/edu/qcif/xnat/openid/openid-auth-plugin`](https://nrgxnat.jfrog.io/nrgxnat/libs-snapshot/au/edu/qcif/xnat/openid/openid-auth-plugin/)

   For example, to fetch the 1.5.0 release:

   `curl -LO https://nrgxnat.jfrog.io/nrgxnat/libs-release/au/edu/qcif/xnat/openid/openid-auth-plugin/1.5.0/openid-auth-plugin-1.5.0-xpl.jar`

1. Copy the plugin jar to your plugins folder:

   `cp openid-auth-plugin-1.5.0-xpl.jar /data/xnat/home/plugins`

### 2. Build the code and generate the JAR

To build the XNAT OpenID authentication provider plugin:

1. If you haven't already, clone [this repository](https://github.com/NrgXnat/openid-auth-plugin.git) and cd to the newly cloned folder.

1. Build the plugin:

   `./gradlew clean xnatPluginJar`

   On Windows, you can use the batch file:

   `gradlew.bat clean xnatPluginJar`

   This builds the plugin jar as **build/libs/openid-auth-plugin-_&lt;version&gt;_-xpl.jar**, where the version
   comes from `build.gradle` (`1.6.0-SNAPSHOT` at the time of writing).

1. Optionally run the tests:

   `./gradlew clean test`

1. Copy the plugin jar to your plugins folder:

   `cp build/libs/openid-auth-plugin-1.6.0-SNAPSHOT-xpl.jar /data/xnat/home/plugins`

## Configuring and Testing

After deploying the plugin, you will need to configure it.

XNAT searches for authentication plugin configurations by looking for files whose names match the pattern:

    *-provider.properties

It looks in the following locations:

- On the classpath in the folder **META-INF/xnat/auth**
- In a folder named **auth** under the XNAT home folder (usually configured with the **xnat.home** system variable)

This plugin will use any entries located in any of those properties files where the property **type** is set to "openid". See the sample properties in the resources directory.

Multiple open-id authentication servers can be configured using multiple properties file. 

The following properties control the plugin:

### provider.id

An authentication provider is identified using the `provider.id` value. The value should be unique across all authentication providers deployed in XNAT. `localdb` is a reserved provider id for the authentication performed by XNAT using the database.

### siteUrl

The main domain, needed to build the full `preEstablishedRedirUri`

### preEstablishedRedirUri

The return leg of OpenID request after the provider has authenticated, defaults to `<siteUrl>/openid-login`

### openid.`providerId`.clientId

The ID obtained on app registration

### openid.`providerId`.clientSecret

The Secret obtained on app registration

### openid.`providerId`.scopes

Controls the scopes returned by the server: `openid,profile,email`

### openid.`providerId`.link

Controls the link HTML snippet displayed on the Login page for this provider. Location of the link text can optionally be customised by modifying `Login.vm`.

### openid.`providerId`.autoLogin

When set to `true`, an unauthenticated visitor to the XNAT login page is automatically sent into this provider's OpenID flow using OIDC `prompt=none`, skipping the "Sign in with …" button. If the visitor already has a session at the provider they are logged straight into XNAT; if not, the provider reports that interaction is required and XNAT quietly shows the normal login page. Defaults to `false`.

The automatic attempt is guarded by a short-lived cookie (about two minutes) so a signed-out visitor is not caught in a redirect loop; once it expires a later visit will try again — which also means a visitor who has since signed in to the provider gets picked up. Only anonymous visitors are redirected, and the provider must support `prompt=none`.

Multiple OpenID providers can be configured on the same XNAT alongside this feature; their normal "Sign in with …" links still appear whenever the automatic attempt does not sign the visitor straight in. Only one provider may enable `autoLogin`, though — if more than one does, the first is used and a warning is logged. Because a visitor who already has a session at the auto-login provider is signed in through it before the login page is shown, `autoLogin` is best suited to a deployment with a single primary identity provider.

An XNAT session timeout ("auto-logout") is routed through XNAT's logout so it isn't silently undone by auto-login, and — with `logoutUri` set — it makes the same best-effort logout at the provider that an explicit logout does. One caveat is specific to a timeout: the login's ID token has expired along with the session, so there is no `id_token_hint` to send. A proxy-style `logoutUri` (e.g. oauth2-proxy `/oauth2/sign_out`) does not need one and logs out fully; a provider end-session endpoint that requires the hint (e.g. Keycloak's) will instead show a "Do you want to log out?" page, which an idle user will not answer — so the XNAT session still ends, but the provider (SSO) session lingers until it expires on its own. Point `logoutUri` at a proxy sign-out if you want a timeout to fully clear SSO. A manual logout always has the ID token and logs out cleanly either way.

### openid.`providerId`.logoutUri

The provider's end-session (RP-initiated logout) endpoint — for Keycloak, `https://<keycloak>/realms/<realm>/protocol/openid-connect/logout`. Only meaningful together with `autoLogin`.

With `autoLogin` on, logging out of XNAT could otherwise be undone immediately: if the provider session is still active, the next automatic `prompt=none` request logs the user straight back in. The plugin uses one of two strategies — never both — depending on whether `logoutUri` is set:

- **`logoutUri` not set — local logout:** the provider (SSO) session lives on, so on logout the plugin sets a short-lived cookie that keeps the login page showing (no automatic re-login) until the user signs in again. Works even without provider end-session support, but the user has to click to sign back in.
- **`logoutUri` set — unified logout:** the plugin performs [OpenID Connect RP-Initiated Logout](https://openid.net/specs/openid-connect-rpinitiated-1_0.html), redirecting to the provider's end-session endpoint (with `id_token_hint`, `post_logout_redirect_uri`, and `client_id`) to end the provider (SSO) session, then back to the XNAT login page. Because the session is actually ended, **no** suppression cookie is set — so after the user signs back in, auto-login works normally. This is the standard, spec-defined logout and the recommended option.

Behind an edge proxy that already brokers OIDC (e.g. oauth2-proxy), point `logoutUri` at the proxy's sign-out endpoint rather than the provider's directly — it clears the proxy's own session too and chains to the provider's end-session.

Notes: with unified logout the provider must allow XNAT's post-logout redirect URI, so register the XNAT login URL as an allowed post-logout redirect on the client. Sending `id_token_hint` requires the ID token, which the plugin keeps server-side (never in a browser cookie, never readable by JavaScript) and stores only when `logoutUri` is set. Per the RP-Initiated Logout spec the hint does travel in the end-session redirect URL, so it reaches browser history and the provider's logs — note it is an audience-restricted ID token, not an access or refresh token.

### openid.`providerId`.shouldFilterEmailDomains

Controls whether domains of the email should be compared against the whitelist: `allowedEmailDomains`.

### openid.`providerId`.allowedEmailDomains

Comma delimted whitelist of domains.

### openid.`providerId`.forceUserCreate

Allows skipping of user creation, usually set to true.

### Claim-validation gates (audience, role, and type)

Three optional gates can reject a valid token whose claims do not meet an authorization
requirement. All are **opt-in and default off**, and run independently on two paths: the
interactive **ID-token** path (`idToken`) and the **bearer-token** path (`bearer`). A rejected user
is denied — they are not routed to the admin auto-enroll queue.

Configuration has two layers: **what** to check and **whether** to check it. Every property in
both layers resolves the same way: a shared per-provider value (e.g.
`openid.providerId.roleCheck.rolePath`, `openid.providerId.audCheck.enabled`) applies to all paths,
and a path-scoped value (e.g. `openid.providerId.bearer.roleCheck.rolePath`,
`openid.providerId.idToken.audCheck.enabled`) overrides it for that path. The path-scoped value
wins when set, otherwise the shared value is used. Because a path-scoped value always wins, a
path-scoped `enabled=false` overrides a shared `enabled=true`, letting one path opt out of a gate
enabled for the provider as a whole.

#### openid.`providerId`.audCheck.acceptedAudiences

Comma-delimited list of accepted audiences. The audience gate passes if the token's `aud` claim
contains at least one of these (a membership test). Recommended posture is a single audience; listing
more than one widens the trust boundary.

#### openid.`providerId`.roleCheck.rolePath

Dot-delimited path to the roles claim, e.g. `resource_access.xnat.roles` (Keycloak). The role gate
reads the structured, possibly nested claim at this path.

#### openid.`providerId`.roleCheck.requiredRoles

Comma-delimited list of roles. The role gate passes if the token's roles contain at least one of
these (any-of).

#### openid.`providerId`.audCheck.enabled / openid.`providerId`.roleCheck.enabled

Enable the audience / role gate on all paths. Default `false`. A path-scoped toggle (below)
overrides this for an individual path.

#### openid.`providerId`.idToken.audCheck.enabled / openid.`providerId`.idToken.roleCheck.enabled

Enable (or, with `false`, disable) the audience / role gate on the interactive ID-token path,
overriding the shared toggle above for this path. Defaults to the shared toggle, otherwise `false`.

#### openid.`providerId`.bearer.audCheck.enabled / openid.`providerId`.bearer.roleCheck.enabled

Enable (or, with `false`, disable) the audience / role gate on the bearer-token path, overriding the
shared toggle above for this path. Defaults to the shared toggle, otherwise `false`.

#### openid.`providerId`.typCheck.enabled

Enable the type gate. Default `false`. The type gate rejects a token whose `typ` is not one of the
accepted values, letting you distinguish an access token from an id token and reject one presented on
the wrong path. Because the gate applies equally to both paths, this shared toggle is the natural
place to turn it on; a path-scoped `idToken.typCheck.enabled` / `bearer.typCheck.enabled` can still
override it for one path. The gate reads `typ` from the token **body** claim first
(e.g. Keycloak `"typ":"Bearer"`/`"ID"`), falling back to the JWT **header** when the body has none
(e.g. RFC 9068 / IdentityServer `"typ":"at+jwt"` for access tokens, `"JWT"` for id tokens). It only
works if your provider emits a `typ` that distinguishes the token kinds.

#### openid.`providerId`.bearer.typCheck.expectedTypes / openid.`providerId`.idToken.typCheck.expectedTypes

Comma-delimited list of accepted `typ` values for that path (a case-sensitive any-of test). **Set
this per path**, because the expected type legitimately differs between the two paths (e.g. bearer
`at+jwt,Bearer` versus idToken `JWT,ID`). A shared `openid.providerId.typCheck.expectedTypes` is
supported by the resolution rules but discouraged: a single value would be wrong for at least one
path. Enabling the gate with no `expectedTypes` for a path rejects every token on it (fail-closed).

### Bearer-token authentication

In addition to the interactive login flow, the plugin can authenticate REST requests that present
an access token minted by the OpenID provider:

```
Authorization: Bearer <jwt>
```

This path is **opt-in per provider** and **off by default**. When enabled, the bearer filter runs
on every request but is a strict no-op unless an `Authorization: Bearer` header is present, and it
short-circuits when the request is already authenticated (e.g. a session cookie). A bearer-
authenticated request is **stateless** — no XNAT session (`JSESSIONID`) is created for it.

Because a bearer token arrives from an untrusted client (unlike the interactive ID token, which
XNAT receives directly from the token endpoint), it is fully validated: the RSA signature is
verified against the provider's published keys, and the `iss` and `exp` claims are checked. Only
the `RS256`/`RS384`/`RS512` algorithms are accepted.

Once the token is validated, a bearer caller is held to the **same account policy as an interactive
login** for that provider: the per-provider email-domain whitelist
(`openid.providerId.shouldFilterEmailDomains` / `allowedEmailDomains`) and the site-wide email
verification requirement both apply. The interactive path redirects the browser when these fail; the
REST path can only return **403**.

**Status codes:**

| Condition | Status |
|-----------|--------|
| Token invalid, expired, wrong/unknown issuer, or unverifiable | **401 Unauthorized** |
| Token valid but fails a `bearer.*` claim gate (including the audience gate, on by default) | **403 Forbidden** |
| Token valid but the identity's email domain is not on the whitelist | **403 Forbidden** |
| Token valid but no XNAT account is mapped (and auto-create is off) | **403 Forbidden** |
| Token valid but the account is disabled, unverified (when site requires verification), or locked | **403 Forbidden** |

A bearer caller resolves to the same XNAT user that a prior interactive login would create for that
identity (both derive `auth_user` from the same `usernamePattern`).

> **Audience gate is on by default for the bearer path.** On the bearer path the `aud` claim is the
> confinement boundary that stops a token minted for another client from being replayed against XNAT,
> so `openid.providerId.bearer.audCheck.enabled` **defaults to `true`** (the interactive path stays
> off by default). You must configure `openid.providerId.audCheck.acceptedAudiences` to the
> audience(s) XNAT should accept — **until you do, every bearer token is rejected with 403**
> (fail-closed; a startup warning is logged). To turn the check off (not recommended), set
> `openid.providerId.bearer.audCheck.enabled=false`.

#### openid.`providerId`.bearer.enabled

Master switch for the bearer-token path for this provider. Default `false`. When `true`, both
`openid.providerId.issuer` and `openid.providerId.jwksUri` must also be configured (a provider
missing either is excluded from the bearer path and logged at error level — fail-closed).

#### openid.`providerId`.issuer

The exact `iss` value expected in bearer tokens from this provider. Also used to route an inbound
token to the right provider. Required when `bearer.enabled` is `true`.

#### openid.`providerId`.jwksUri

The provider's JWKS (JSON Web Key Set) endpoint. Its public keys verify the bearer token signature;
the key set is cached and re-fetched on key rotation. Required when `bearer.enabled` is `true`.

#### openid.`providerId`.bearer.forceUserCreate

Whether to auto-create an XNAT account for a validated bearer-token identity that has no existing
mapping. If unset, falls back to the shared `openid.providerId.forceUserCreate`. When neither is
`true`, an unmapped identity is denied with 403.

### auto.enabled

Standard XNAT provider attribute that sets the `enabled` property of new users. Set to `false` to require admins to manually enable users before allowing logins, set to `true` to allow immediate access.

### auto.verified

Standard XNAT provider attribute that sets the `verified` property of new users. Set to `true` to automatically verify new users, `false` to require email verification or manual verification by an administrator.

### openid.`providerId`.userInfoUri

The optional URI of the UserInfo endpoint. If present then a call will be exchanged to this endpoint to collect additional information about the user.

### openid.`providerId`.\*Property

The property names used to populate user information during user creation. These are the property names from the information returned from the authentication provider.

### openid.`providerId`.pkceEnabled

Flag to enable the PKCE feature in the authorization code grant flow

### openid.`providerId`.usernamePattern

Default pattern to define `auth_user` field of the `xhbm_xdat_user_auth` table

### openid.`providerId`.idTokenEncryptionAlgorithm

Optional algorithm for ID token encryption. When configured, XNAT will generate and publish public encryption keys that OpenID providers can use to encrypt ID tokens before sending them to XNAT.

Supported algorithms: `RSA1_5`, `RSA-OAEP`, `RSA-OAEP-256`, `RSA-OAEP-384`, `RSA-OAEP-512`

Example: `openid.keycloak.idTokenEncryptionAlgorithm=RSA-OAEP-256`

## ID Token Encryption and Key Management

When ID token encryption is configured, XNAT automatically manages encryption keys as follows:

### Key Storage and Persistence

- **Database-backed storage**: Encryption keys are stored in the XNAT database (in the preferences system)
- **Automatic sharing**: Keys are automatically shared across all nodes in load-balanced environments
- **Persistent across restarts**: Keys are generated once and reused on subsequent Tomcat restarts
- **No manual configuration required**: Keys are automatically generated on first startup if they don't exist

### Public Key Endpoint

OpenID providers can retrieve public keys from the JWKS (JSON Web Key Set) endpoint:

```
https://your-xnat-domain/xapi/openid/.well-known/jwks.json
```

This endpoint is publicly accessible and returns only public keys (private keys remain secure in the database).

### Key Rotation

To rotate encryption keys:

1. Delete the stored key from the XNAT database directly via SQL:
   ```sql
   DELETE FROM xhbm_preference p
   USING xhbm_tool t
   WHERE t.id = p.tool
     AND t.tool_id = 'openid'
     AND p.name = 'jwk-RSA-OAEP-256';
   ```
2. Restart **all** Tomcat instances (the primary node will generate a new key on startup)
3. Update your OpenID provider to fetch the new public key from the JWKS endpoint

**Note:** All nodes must be restarted to pick up the new key. Simply deleting from the database won't update in-memory keys on running nodes.

### Key Status API

Check if a key exists in the database (admin-only):
```bash
curl -u admin:password https://your-xnat/xapi/openid/keys/RSA-OAEP-256
```

Returns `true` if the key exists, `false` otherwise.

### Backup and Recovery

- **Backup**: Encryption keys are included in standard XNAT database backups
- **Recovery**: Restore the database to recover keys
- **Important**: If keys are lost, OpenID providers must re-fetch the new public key after key regeneration

### Load-Balanced Environments

No special configuration is required for load-balanced environments:

- All nodes automatically share the same keys via the database
- No file synchronization needed
- No per-node key generation issues

#### Startup Behavior in Multi-Node Environments

When encryption is enabled:

- **Primary node**: Generates encryption keys on first startup and persists them to the database
- **Non-primary nodes**: Wait for the primary node to generate keys, checking the database with exponential backoff
- **Timeout**: Non-primary nodes will retry for up to ~5 minutes before failing if keys are not available

**Important considerations:**

1. **Startup order**: If all nodes start simultaneously, non-primary nodes will wait for the primary node to complete key generation
2. **Primary node delays**: If the primary node is slow to start or fails during startup, non-primary nodes may timeout waiting for keys
3. **Recommendations**:
   - For initial deployment with encryption enabled, start the primary node first
   - Ensure the primary node is healthy before starting additional nodes
   - Monitor logs on non-primary nodes for key loading status
   - In case of timeout errors, verify the primary node has started successfully and keys are in the database

## Sample Configuration

[Sample configuration files are found here.](src/main/resources/) Please note the need to rename these files before usage, see opening section of the file.

## License

This plugin is released under the [Simplified BSD (2-clause) license](LICENSE), the same license used by
XNAT itself. It was originally developed by the Queensland Cyber Infrastructure Foundation under the GNU
General Public License and was relicensed with the permission of the original authors.

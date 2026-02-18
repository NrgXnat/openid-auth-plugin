package au.edu.qcif.xnat.auth.openid.pkce;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.*;

import lombok.Getter;
import lombok.Setter;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.lang3.StringUtils;
import org.springframework.http.HttpHeaders;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.oauth2.client.filter.state.StateKeyGenerator;
import org.springframework.security.oauth2.client.resource.OAuth2AccessDeniedException;
import org.springframework.security.oauth2.client.resource.OAuth2ProtectedResourceDetails;
import org.springframework.security.oauth2.client.resource.UserApprovalRequiredException;
import org.springframework.security.oauth2.client.resource.UserRedirectRequiredException;
import org.springframework.security.oauth2.client.token.AccessTokenRequest;
import org.springframework.security.oauth2.client.token.grant.code.AuthorizationCodeAccessTokenProvider;
import org.springframework.security.oauth2.client.token.grant.code.AuthorizationCodeResourceDetails;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.exceptions.InvalidRequestException;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

import lombok.extern.slf4j.Slf4j;

import static au.edu.qcif.xnat.auth.openid.etc.OpenIdAuthConstant.CHUNK_SEPARATOR;

@SuppressWarnings("deprecation")
@Setter
@Slf4j
public class PkceAuthorizationCodeAccessTokenProvider extends AuthorizationCodeAccessTokenProvider {

	private final RandomValueStringGenerator generator;
	private final StateKeyGenerator          stateKeyGenerator;

	private boolean stateMandatory = true;

	public PkceAuthorizationCodeAccessTokenProvider(final int stateKeyLength) {
		generator = new RandomValueStringGenerator(stateKeyLength);
		stateKeyGenerator = resource -> generator.generate();
	}

	@Override
	public OAuth2AccessToken obtainAccessToken(OAuth2ProtectedResourceDetails details, AccessTokenRequest request)
			throws UserRedirectRequiredException, UserApprovalRequiredException, AccessDeniedException,
			OAuth2AccessDeniedException {
		PkceAuthorizationCodeResourceDetails resource = (PkceAuthorizationCodeResourceDetails) details;

		if (request.getAuthorizationCode() == null) {
			if (request.getStateKey() == null) {
				throw getRedirectForAuthorization(resource, request);
			}
			obtainAuthorizationCode(resource, request);
		}
		return retrieveToken(request, resource, getParametersForTokenRequest(resource, request), new HttpHeaders());

	}

	private MultiValueMap<String, String> getParametersForTokenRequest(AuthorizationCodeResourceDetails details, AccessTokenRequest request) {
		PkceAuthorizationCodeResourceDetails resource = (PkceAuthorizationCodeResourceDetails) details;

		MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
		form.set("grant_type", "authorization_code");
		form.set("code", request.getAuthorizationCode());

		final Object preservedState = request.getPreservedState();

		// The token endpoint has no use for the state, so we don't send it back, but we
		// are using it for CSRF detection client side...
		if ((request.getStateKey() != null || stateMandatory) && preservedState == null) {
			throw new InvalidRequestException("Possible CSRF detected - state parameter was required but no state could be found");
		}

		if (resource.isPkceEnabled() && preservedState instanceof PreservedState) {
			final String codeVerifier = ((PreservedState) preservedState).getCodeVerifier();
			form.set("code_verifier", codeVerifier);
			log.debug("Code verifier parameter added: {}", codeVerifier);
		}

		// Extracting the redirect URI from a saved request should ignore the current URI, so it's not simply a call to
		// resource.getRedirectUri(). Try to get the redirect uri from the stored state, fall back to
		// resource.getRedirectUri().
		final String redirectUri;
		if (preservedState instanceof String) {
			redirectUri = String.valueOf(preservedState);
		} else if (preservedState instanceof PreservedState && StringUtils.isNotBlank(((PreservedState) preservedState).getRedirectUri())) {
			redirectUri = ((PreservedState) preservedState).getRedirectUri();
		} else {
			redirectUri = resource.getRedirectUri(request);
		}

		if (StringUtils.isNotBlank(redirectUri) && !StringUtils.equals("NONE", redirectUri)) {
			form.set("redirect_uri", redirectUri);
		}

		return form;
	}

	private UserRedirectRequiredException getRedirectForAuthorization(final AuthorizationCodeResourceDetails details, final AccessTokenRequest request) {
		final PkceAuthorizationCodeResourceDetails resource = (PkceAuthorizationCodeResourceDetails) details;

		// we don't have an authorization code yet. So first get that.
		final TreeMap<String, String> requestParameters = new TreeMap<>();
		requestParameters.put("response_type", "code"); // oauth2 spec, section 3
		requestParameters.put("client_id", resource.getClientId());

		String codeVerifier = null;
		if (resource.isPkceEnabled()) {
			log.debug("Adding parameters related to PKCE");
			codeVerifier = generateKey();
			try {
				requestParameters.put("code_challenge", createHash(codeVerifier));
				requestParameters.put("code_challenge_method", "S256");
				log.debug("code_challenge and code_challenge_method parameters added");
			} catch (Exception e) {
				requestParameters.put("code_challenge", codeVerifier);
				log.debug("code_challenge parameter added");
			}
		} else {
			log.debug("PKCE is disabled");
		}

		// Client secret is not required in the initial authorization request

		final String redirectUri = resource.getRedirectUri(request);
		if (StringUtils.isNotBlank(redirectUri)) {
			requestParameters.put("redirect_uri", redirectUri);
		}

		if (resource.isScoped()) {
			requestParameters.put("scope", String.join(" ", Optional.ofNullable(resource.getScope()).orElseGet(Collections::emptyList)));
		}

		final UserRedirectRequiredException redirectException = new UserRedirectRequiredException(resource.getUserAuthorizationUri(), requestParameters);

		final String stateKey = stateKeyGenerator.generateKey(resource);
		redirectException.setStateKey(stateKey);
		request.setStateKey(stateKey);
		redirectException.setStateToPreserve(new PreservedState(redirectUri, codeVerifier));
		request.setPreservedState(new PreservedState(redirectUri, codeVerifier));

		return redirectException;
	}

	private static String createHash(String value) throws NoSuchAlgorithmException {
		MessageDigest md = MessageDigest.getInstance("SHA-256");
		byte[] digest = md.digest(value.getBytes(StandardCharsets.US_ASCII));
		return encodeToByte64String(digest);
	}

	private static String generateKey() {
		byte[] bytes = new byte[96];
		SecureRandom random = new SecureRandom();
		random.nextBytes(bytes);
		return encodeToByte64String(bytes);
	}

	private static String encodeToByte64String(byte[] bytes) {
		return new Base64(0, CHUNK_SEPARATOR, true).encodeAsString(bytes);
	}

	@Getter
	static class PreservedState {
		private final String redirectUri;
		private final String codeVerifier;
		
		public PreservedState(String redirectUri, String codeVerifier) {
			this.redirectUri = redirectUri;
			this.codeVerifier = codeVerifier;
		}
	}
}

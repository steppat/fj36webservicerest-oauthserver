package br.com.caelum.oauth.endpoints;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.oltu.oauth2.as.issuer.MD5Generator;
import org.apache.oltu.oauth2.as.issuer.OAuthIssuer;
import org.apache.oltu.oauth2.as.issuer.OAuthIssuerImpl;
import org.apache.oltu.oauth2.as.request.OAuthTokenRequest;
import org.apache.oltu.oauth2.as.response.OAuthASResponse;
import org.apache.oltu.oauth2.common.OAuth;
import org.apache.oltu.oauth2.common.error.OAuthError;
import org.apache.oltu.oauth2.common.exception.OAuthProblemException;
import org.apache.oltu.oauth2.common.exception.OAuthSystemException;
import org.apache.oltu.oauth2.common.message.OAuthResponse;
import org.apache.oltu.oauth2.common.message.types.GrantType;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import br.com.caelum.oauth.SecurityCodeStorage;
import br.com.caelum.oauth.ServerParams;

@RestController
@RequestMapping("/token")
public class TokenEndpoint {

	public static final String INVALID_CLIENT_DESCRIPTION = "Client authentication failed "
			                                              + "(e.g., unknown client, no client "
			                                              + "authentication included, or unsupported "
			                                              + "authentication method).";

	@Autowired
	private SecurityCodeStorage securityCodeStorage;

	@PostMapping(consumes=MediaType.APPLICATION_JSON_VALUE, produces=MediaType.APPLICATION_JSON_VALUE)
	public ResponseEntity<?> authorize(HttpServletRequest request)
			throws OAuthSystemException {
		try {
			OAuthTokenRequest oauthRequest = new OAuthTokenRequest(request);
			OAuthIssuer oauthIssuerImpl = new OAuthIssuerImpl(
					new MD5Generator());

			if (!checkClientId(oauthRequest.getClientId())) {
				return buildInvalidClientIdResponse();
			}

			if (!checkClientSecret(oauthRequest.getClientSecret())) {
				return buildInvalidClientSecretResponse();
			}

			if (oauthRequest.getParam(OAuth.OAUTH_GRANT_TYPE).equals(
					GrantType.AUTHORIZATION_CODE.toString())) {
				if (!checkAuthCode(oauthRequest.getParam(OAuth.OAUTH_CODE))) {
					return buildBadAuthCodeResponse();
				}
			} else if (oauthRequest.getParam(OAuth.OAUTH_GRANT_TYPE).equals(
					GrantType.PASSWORD.toString())) {
				if (!checkUserPass(oauthRequest.getUsername(),
						oauthRequest.getPassword())) {
					return buildInvalidUserPassResponse();
				}
			} else if (oauthRequest.getParam(OAuth.OAUTH_GRANT_TYPE).equals(
					GrantType.REFRESH_TOKEN.toString())) {
				// not supported in this implementation
				buildInvalidUserPassResponse();
			}

			final String accessToken = oauthIssuerImpl.accessToken();

			securityCodeStorage.addToken(accessToken);

			OAuthResponse response = OAuthASResponse
					.tokenResponse(HttpServletResponse.SC_OK)
					.setAccessToken(accessToken).setExpiresIn("3600")
					.buildJSONMessage();

			return ResponseEntity.status(response.getResponseStatus())
					.body(response.getBody());

		} catch (OAuthProblemException e) {
			OAuthResponse res = OAuthASResponse
					.errorResponse(HttpServletResponse.SC_BAD_REQUEST).error(e)
					.buildJSONMessage();
			return ResponseEntity.status(res.getResponseStatus())
					.body(res.getBody());
		}
	}

	@GetMapping("/{token}")
	public ResponseEntity<?> exists(@PathVariable("token") String token) {
		if (securityCodeStorage.isValidToken(token)) {
			return ResponseEntity.ok().build();
		} else {
			return ResponseEntity.notFound().build();
		}
	}

	private ResponseEntity<String> buildInvalidClientIdResponse() throws OAuthSystemException {
		OAuthResponse response = OAuthASResponse
				.errorResponse(HttpServletResponse.SC_BAD_REQUEST)
				.setError(OAuthError.TokenResponse.INVALID_CLIENT)
				.setErrorDescription(INVALID_CLIENT_DESCRIPTION)
				.buildJSONMessage();
		return ResponseEntity.status(response.getResponseStatus()).body(response.getBody());
	}

	private ResponseEntity<String> buildInvalidClientSecretResponse()
			throws OAuthSystemException {
		OAuthResponse response = OAuthASResponse
				.errorResponse(HttpServletResponse.SC_UNAUTHORIZED)
				.setError(OAuthError.TokenResponse.UNAUTHORIZED_CLIENT)
				.setErrorDescription(INVALID_CLIENT_DESCRIPTION)
				.buildJSONMessage();
		return ResponseEntity.status(response.getResponseStatus())
				.body(response.getBody());
	}

	private ResponseEntity<String> buildBadAuthCodeResponse() throws OAuthSystemException {
		OAuthResponse response = OAuthASResponse
				.errorResponse(HttpServletResponse.SC_BAD_REQUEST)
				.setError(OAuthError.TokenResponse.INVALID_GRANT)
				.setErrorDescription("invalid authorization code")
				.buildJSONMessage();
		return ResponseEntity.status(response.getResponseStatus())
				.body(response.getBody());
	}

	private ResponseEntity<String> buildInvalidUserPassResponse() throws OAuthSystemException {
		OAuthResponse response = OAuthASResponse
				.errorResponse(HttpServletResponse.SC_BAD_REQUEST)
				.setError(OAuthError.TokenResponse.INVALID_GRANT)
				.setErrorDescription("invalid username or password")
				.buildJSONMessage();
		return ResponseEntity.status(response.getResponseStatus())
				.body(response.getBody());
	}

	private boolean checkClientId(String clientId) {
		return ServerParams.CLIENT_ID.equals(clientId);
	}

	private boolean checkClientSecret(String secret) {
		return ServerParams.CLIENT_SECRET.equals(secret);
	}

	private boolean checkAuthCode(String authCode) {
		return securityCodeStorage.isValidAuthCode(authCode);
	}

	private boolean checkUserPass(String user, String pass) {
		return ServerParams.PASSWORD.equals(pass) && ServerParams.USERNAME.equals(user);
	}
}
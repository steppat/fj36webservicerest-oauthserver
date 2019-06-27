package br.com.caelum.oauth.endpoints;

import java.net.URI;
import java.net.URISyntaxException;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.oltu.oauth2.as.issuer.MD5Generator;
import org.apache.oltu.oauth2.as.issuer.OAuthIssuerImpl;
import org.apache.oltu.oauth2.as.request.OAuthAuthzRequest;
import org.apache.oltu.oauth2.as.response.OAuthASResponse;
import org.apache.oltu.oauth2.common.OAuth;
import org.apache.oltu.oauth2.common.exception.OAuthProblemException;
import org.apache.oltu.oauth2.common.exception.OAuthSystemException;
import org.apache.oltu.oauth2.common.message.OAuthResponse;
import org.apache.oltu.oauth2.common.message.types.ResponseType;
import org.apache.oltu.oauth2.common.utils.OAuthUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import br.com.caelum.oauth.SecurityCodeStorage;

@RestController
@RequestMapping("/auth")
public class AuthEndpoint {

	@Autowired
	private SecurityCodeStorage securityCodeStorage;

	@GetMapping
	public ResponseEntity<?> authorize(HttpServletRequest request) throws URISyntaxException, OAuthSystemException {
		
		try {
			
			OAuthAuthzRequest oauthRequest = new OAuthAuthzRequest(request);
			
			OAuthIssuerImpl oauthIssuerImpl = new OAuthIssuerImpl(new MD5Generator());

			String responseType = oauthRequest
					.getParam(OAuth.OAUTH_RESPONSE_TYPE);

			OAuthASResponse.OAuthAuthorizationResponseBuilder builder = OAuthASResponse
					.authorizationResponse(request,
							HttpServletResponse.SC_FOUND);

			if (responseType.equals(ResponseType.CODE.toString())) {
				
				final String authorizationCode = oauthIssuerImpl
						.authorizationCode();
				
				securityCodeStorage.addAuthCode(authorizationCode);
				
				builder.setCode(authorizationCode);
				
			} 

			String redirectURI = oauthRequest
					.getParam(OAuth.OAUTH_REDIRECT_URI);
			
			final OAuthResponse response = builder.location(redirectURI)
					.buildQueryMessage();
			
			URI url = new URI(response.getLocationUri());
			
			return ResponseEntity.created(url).build();
			
		} catch (OAuthProblemException e) {
			
			String redirectUri = e.getRedirectUri();

			if (OAuthUtils.isEmpty(redirectUri)) {
				return ResponseEntity.badRequest().body("OAuth callback url needs to be provided by client!!!");
			}
			
			final OAuthResponse response = OAuthASResponse
					.errorResponse(HttpServletResponse.SC_FOUND).error(e)
					.location(redirectUri).buildQueryMessage();
			
			final URI location = new URI(response.getLocationUri());

			return ResponseEntity.created(location).build();
								
		}
	}
}

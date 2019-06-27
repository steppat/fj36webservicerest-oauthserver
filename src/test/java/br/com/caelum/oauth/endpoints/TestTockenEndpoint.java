package br.com.caelum.oauth.endpoints;

import org.apache.oltu.oauth2.client.OAuthClient;
import org.apache.oltu.oauth2.client.URLConnectionClient;
import org.apache.oltu.oauth2.client.request.OAuthClientRequest;
import org.apache.oltu.oauth2.client.response.OAuthAccessTokenResponse;
import org.apache.oltu.oauth2.common.exception.OAuthProblemException;
import org.apache.oltu.oauth2.common.exception.OAuthSystemException;
import org.apache.oltu.oauth2.common.message.types.GrantType;
import org.junit.Test;

public class TestTockenEndpoint {

	public static void main(String[] args) throws OAuthSystemException, OAuthProblemException {

		String tokenEndpoint = "http://localhost:8080/oauth/token";
		
		OAuthClientRequest request = OAuthClientRequest.tokenLocation(tokenEndpoint).setGrantType(GrantType.PASSWORD)
				.setClientId("oauth2_client_id").setClientSecret("oauth2_client_secret").setUsername("fake_user")
				.setPassword("passwd").buildBodyMessage();
		
		OAuthClient oAuthClient = new OAuthClient(new URLConnectionClient());
		OAuthAccessTokenResponse oauthResponse = oAuthClient.accessToken(request);
		
		System.out.println("Access token: " + oauthResponse.getAccessToken());
		System.out.println("Expira em: " + oauthResponse.getExpiresIn());
	}

}

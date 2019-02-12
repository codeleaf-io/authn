package io.codeleaf.authn.jaxrs.oauth.linkedin;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.scribejava.core.model.OAuth2AccessToken;
import com.github.scribejava.core.model.OAuthRequest;
import com.github.scribejava.core.model.Verb;
import com.github.scribejava.core.oauth.OAuth20Service;
import io.codeleaf.common.utils.Types;

import java.io.IOException;
import java.util.Map;
import java.util.concurrent.ExecutionException;

public class LinkedInDataProvider {

    private static final String PROTECTED_RESOURCE_URL = "https://api.linkedin.com/v1/people/~";


    public static Map<String, Object> getProfileDetails(OAuth2AccessToken accessToken, OAuth20Service linkedInService) throws InterruptedException, ExecutionException, IOException {
        final OAuthRequest request = new OAuthRequest(Verb.GET, PROTECTED_RESOURCE_URL);
        request.addHeader("x-li-format", "json");
        request.addHeader("Accept-Language", "en-US,en;q=0.5");
        linkedInService.signRequest(accessToken, request);
        final com.github.scribejava.core.model.Response response = linkedInService.execute(request);
        ObjectMapper mapper = new ObjectMapper();
        Map<String, Object> map = Types.cast(mapper.readValue(response.getBody(), Map.class));
        map.put("token", accessToken.getAccessToken());
        return map;
    }
}

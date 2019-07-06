package io.codeleaf.authn.jaxrs.oauth.linkedin;

import com.github.scribejava.core.builder.api.DefaultApi20;
import com.github.scribejava.core.httpclient.HttpClient;
import com.github.scribejava.core.httpclient.HttpClientConfig;
import com.github.scribejava.core.oauth.OAuth20Service;

public class LinkedInOAuth20Service extends OAuth20Service {

    private final String landingPageUrl;

    public LinkedInOAuth20Service(DefaultApi20 api, String apiKey, String apiSecret, String callback, String scope, String state, String responseType, String userAgent, HttpClientConfig httpClientConfig, HttpClient httpClient, String landingPageUrl) {
        super(api, apiKey, apiSecret, callback, scope, state, responseType, userAgent, httpClientConfig, httpClient);
        this.landingPageUrl = landingPageUrl;
    }

    public LinkedInOAuth20Service(OAuth20Service oAuth20Service, String landingPageUrl) {
        super(oAuth20Service.getApi(),
                oAuth20Service.getApiKey(),
                oAuth20Service.getApiSecret(),
                oAuth20Service.getCallback(), oAuth20Service.getScope(),
                oAuth20Service.getState(),
                oAuth20Service.getResponseType(),
                null, null, null);
        this.landingPageUrl = landingPageUrl;
    }

    public String getLandingPageUrl() {
        return landingPageUrl;
    }
}

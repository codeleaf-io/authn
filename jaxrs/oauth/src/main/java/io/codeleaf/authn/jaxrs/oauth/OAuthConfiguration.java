package io.codeleaf.authn.jaxrs.oauth;

import io.codeleaf.config.Configuration;

import java.net.URI;

public class OAuthConfiguration implements Configuration {

    private final String clientId;
    private final String clientSecret;
    private final URI redirectUri;
    private final String scope;
    private final String state;

    public OAuthConfiguration(String clientId, String clientSecret, URI redirectUri, String scope, String state) {
        this.clientId = clientId;
        this.clientSecret = clientSecret;
        this.redirectUri = redirectUri;
        this.scope = scope;
        this.state = state;
    }

    public String getClientSecret() {
        return clientSecret;
    }

    public String getClientId() {
        return clientId;
    }

    public URI getRedirectUri() {
        return redirectUri;
    }

    public String getScope() {
        return scope;
    }

    public String getState() {
        return state;
    }
}

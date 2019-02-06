package io.codeleaf.authn.jaxrs.oauth.linkedin;

import com.github.scribejava.apis.LinkedInApi20;
import com.github.scribejava.core.builder.ServiceBuilder;
import com.github.scribejava.core.oauth.OAuth20Service;
import io.codeleaf.authn.jaxrs.oauth.OAuthConfiguration;

public final class LinkedInServiceFactory {

    private LinkedInServiceFactory() {
    }

    public static LinkedInOAuth20Service create(OAuthConfiguration configuration) {
        OAuth20Service oAuth20Service = new ServiceBuilder(configuration.getClientId())
                .apiSecret(configuration.getClientSecret())
                .scope(configuration.getScope())
                .callback(configuration.getRedirectUri().toString())
                .state(configuration.getState())
                .build(LinkedInApi20.instance());
        return new LinkedInOAuth20Service(oAuth20Service, configuration.getLandingPageUrl());
    }
}

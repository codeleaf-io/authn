package io.codeleaf.authn.jaxrs.oauth;

import io.codeleaf.authn.jaxrs.spi.JaxrsRequestAuthenticator;

public abstract class OAuthAuthenticator implements JaxrsRequestAuthenticator {

    @Override
    public String getAuthenticationScheme() {
        return "OAUTH";
    }
}

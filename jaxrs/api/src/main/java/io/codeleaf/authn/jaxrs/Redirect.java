package io.codeleaf.authn.jaxrs;

import io.codeleaf.authn.AuthenticationContext;
import io.codeleaf.authn.jaxrs.spi.JaxrsRequestAuthenticator;

import javax.ws.rs.container.ContainerRequestContext;
import javax.ws.rs.core.Response;

public final class Redirect implements JaxrsRequestAuthenticator {

    private final RedirectConfiguration configuration;

    public Redirect(RedirectConfiguration configuration) {
        this.configuration = configuration;
    }

    @Override
    public String getAuthenticationScheme() {
        return null;
    }

    @Override
    public AuthenticationContext authenticate(ContainerRequestContext requestContext) {
        return null;
    }

    @Override
    public boolean handleNotAuthenticated(ContainerRequestContext requestContext) {
        requestContext.abortWith(Response.temporaryRedirect(configuration.getRedirectURI()).build());
        return true;
    }
}

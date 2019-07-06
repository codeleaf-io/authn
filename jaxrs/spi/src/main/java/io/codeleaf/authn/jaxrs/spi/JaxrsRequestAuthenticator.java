package io.codeleaf.authn.jaxrs.spi;

import io.codeleaf.authn.AuthenticationContext;
import io.codeleaf.authn.AuthenticationException;

import javax.ws.rs.container.ContainerRequestContext;
import javax.ws.rs.container.ContainerResponseContext;
import javax.ws.rs.container.ResourceInfo;
import javax.ws.rs.core.Response;
import java.io.IOException;

public interface JaxrsRequestAuthenticator {

    String getAuthenticationScheme();

    default AuthenticationContext authenticate(ContainerRequestContext requestContext) throws AuthenticationException {
        return null;
    }

    default HandshakeState setHandshakeState(ContainerRequestContext requestContext, ResourceInfo resourceInfo, HandshakeState extractedState) throws AuthenticationException, IOException {
        return extractedState;
    }

    /**
     * Returns <code>null</code> when we want to continue to the next configured authenticator.
     * Returns a Response when would like to abort, and send the Response as defined using
     * {@link ContainerRequestContext#abortWith(Response)} to the client.
     *
     * @param requestContext
     * @return
     */
    default Response.ResponseBuilder onNotAuthenticated(ContainerRequestContext requestContext) {
        return null;
    }

    default Response.ResponseBuilder onFailureCompleted(ContainerRequestContext requestContext, AuthenticationContext authenticationContext) {
        return null;
    }

    default void onServiceCompleted(ContainerRequestContext requestContext, ContainerResponseContext responseContext, AuthenticationContext context) {
    }

    default Object getResource() {
        return null;
    }
}
package io.codeleaf.authn.jaxrs.spi;

import io.codeleaf.authn.AuthenticationContext;
import io.codeleaf.authn.AuthenticationException;

import javax.ws.rs.container.ContainerRequestContext;
import javax.ws.rs.core.Response;
import java.net.URI;

public interface JaxrsRequestAuthenticator {

    default URI getLoginURI() {
        System.out.println("returning null login url");
        return null;
    }

    String getAuthenticationScheme();

    AuthenticationContext authenticate(ContainerRequestContext requestContext) throws AuthenticationException;

    /**
     * Returns <code>false</code> when we want to continue to the next configured authenticator.
     * Returns <code>true</code> when would like to abort, and send the Response as defined using
     * {@link ContainerRequestContext#abortWith(Response)} to the client.
     *
     * @param requestContext
     * @return
     */
    default boolean handleNotAuthenticated(ContainerRequestContext requestContext) {
        return false;
    }

    default Object getResource() {
        return null;
    }
}
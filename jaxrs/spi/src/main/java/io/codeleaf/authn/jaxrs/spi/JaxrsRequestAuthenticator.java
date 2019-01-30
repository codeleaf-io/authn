package io.codeleaf.authn.jaxrs.spi;

import io.codeleaf.authn.AuthenticationContext;
import io.codeleaf.authn.AuthenticationException;

import javax.ws.rs.container.ContainerRequestContext;
import java.net.URI;
import java.net.URISyntaxException;

public interface JaxrsRequestAuthenticator {

    default URI getLoginURI() throws URISyntaxException {
        System.out.println("returning null login URI.");
        return null;
    }

    default URI getLogoutURI() {
        System.out.println("returning null logout URI.");
        return null;
    }

    String getAuthenticationScheme();

    AuthenticationContext authenticate(ContainerRequestContext requestContext) throws AuthenticationException;

    default Object getResource() {
        return null;
    }
}
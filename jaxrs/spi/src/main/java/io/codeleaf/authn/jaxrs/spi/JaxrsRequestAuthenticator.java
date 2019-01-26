package io.codeleaf.authn.jaxrs.spi;

import io.codeleaf.authn.AuthenticationContext;
import io.codeleaf.authn.AuthenticationException;

import javax.ws.rs.container.ContainerRequestContext;

public interface JaxrsRequestAuthenticator {

    String getAuthenticationScheme();

    AuthenticationContext authenticate(ContainerRequestContext requestContext) throws AuthenticationException;

}

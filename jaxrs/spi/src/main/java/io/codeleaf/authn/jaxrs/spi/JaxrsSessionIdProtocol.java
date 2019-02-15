package io.codeleaf.authn.jaxrs.spi;

import javax.ws.rs.container.ContainerRequestContext;
import javax.ws.rs.core.Response;

public interface JaxrsSessionIdProtocol {

    void setSessionId(ContainerRequestContext requestContext, Response.ResponseBuilder response, String sessionId);

    String getSessionId(ContainerRequestContext requestContext);
}

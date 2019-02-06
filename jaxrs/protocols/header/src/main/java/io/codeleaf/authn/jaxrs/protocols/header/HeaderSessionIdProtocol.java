package io.codeleaf.authn.jaxrs.protocols.header;

import io.codeleaf.authn.jaxrs.spi.JaxrsSessionIdProtocol;

import javax.ws.rs.container.ContainerRequestContext;
import javax.ws.rs.core.Response;

public final class HeaderSessionIdProtocol implements JaxrsSessionIdProtocol {

    private final HeaderSessionIdConfiguration configuration;

    public HeaderSessionIdProtocol(HeaderSessionIdConfiguration configuration) {
        this.configuration = configuration;
    }

    @Override
    public void setSessionId(Response.ResponseBuilder response, String sessionId) {
        response.header(configuration.getHeaderName(), sessionId);
    }

    @Override
    public String getSessionId(ContainerRequestContext requestContext) {
        return requestContext.getHeaderString(configuration.getHeaderName());
    }
}

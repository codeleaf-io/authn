package io.codeleaf.authn.jaxrs.protocols.header;

import io.codeleaf.authn.jaxrs.spi.JaxrsSessionIdProtocol;

import javax.ws.rs.container.ContainerRequestContext;
import javax.ws.rs.core.Response;
import java.util.List;

public final class HeaderSessionIdProtocol implements JaxrsSessionIdProtocol {

    private final HeaderSessionIdConfiguration configuration;

    public HeaderSessionIdProtocol(HeaderSessionIdConfiguration configuration) {
        this.configuration = configuration;
    }

    @Override
    public void setSessionId(ContainerRequestContext requestContext, Response.ResponseBuilder response, String sessionId) {
        response.header(configuration.getHeaderName(), sessionId);
    }

    @Override
    public void clearSessionId(ContainerRequestContext requestContext, Response.ResponseBuilder response, String sessionId) {
    }

    @Override
    public String getSessionId(ContainerRequestContext requestContext) {
        List<String> headers = requestContext.getHeaders().get(configuration.getHeaderName());
        return headers == null || headers.isEmpty() ? null : headers.get(0);
    }
}

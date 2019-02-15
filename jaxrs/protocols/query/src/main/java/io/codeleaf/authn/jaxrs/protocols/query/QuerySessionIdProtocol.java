package io.codeleaf.authn.jaxrs.protocols.query;

import io.codeleaf.authn.jaxrs.spi.JaxrsSessionIdProtocol;

import javax.ws.rs.container.ContainerRequestContext;
import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.Response;
import java.net.URI;

public final class QuerySessionIdProtocol implements JaxrsSessionIdProtocol {

    private final QuerySessionIdConfiguration configuration;

    public QuerySessionIdProtocol(QuerySessionIdConfiguration configuration) {
        this.configuration = configuration;
    }

    @Override
    public void setSessionId(ContainerRequestContext requestContext, Response.ResponseBuilder response, String sessionId) {
        MultivaluedMap<String, Object> headers = response.build().getHeaders();
        Object headerValue = headers.getFirst("Location");
        String header = headerValue == null ? null : headerValue.toString();
        String param = configuration.getParameterName() + "=" + sessionId;
        if (header == null) {
            header = "?" + param;
        } else if (header.contains("?")) {
            header += "&" + param;
        } else {
            header += "?" + param;
        }
        response.location(URI.create(header));
    }

    @Override
    public String getSessionId(ContainerRequestContext requestContext) {
        Object value = requestContext.getUriInfo().getQueryParameters().getFirst(configuration.getParameterName());
        return value == null ? null : value.toString();
    }
}

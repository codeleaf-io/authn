package io.codeleaf.authn.jaxrs.protocols.query;

import io.codeleaf.authn.jaxrs.spi.JaxrsSessionIdProtocol;

import javax.ws.rs.container.ContainerRequestContext;
import javax.ws.rs.core.Response;

public final class QuerySessionIdProtocol implements JaxrsSessionIdProtocol {

    private final QuerySessionIdConfiguration configuration;

    public QuerySessionIdProtocol(QuerySessionIdConfiguration configuration) {
        this.configuration = configuration;
    }

    @Override
    public void setSessionId(Response.ResponseBuilder response, String sessionId) {
        String header = response.build().getStringHeaders().getFirst("Location");
        String param = configuration.getParameterName() + "=" + sessionId;
        if (header == null) {
            header = "?" + param;
        } else if (header.contains("?")) {
            header += "&" + param;
        } else {
            header += "?" + param;
        }
        response.header("Location", param);
    }

    @Override
    public String getSessionId(ContainerRequestContext requestContext) {
        Object value = requestContext.getProperty(configuration.getParameterName());
        return value == null ? null : value.toString();
    }
}

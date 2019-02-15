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
        System.out.println(headers);
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
        headers.remove("Location");
        headers.add("Location", URI.create(header));
        System.out.println(headers);
        response.replaceAll(headers);
        System.out.println("We should have set the session id: " + sessionId);
    }

    @Override
    public String getSessionId(ContainerRequestContext requestContext) {
        Object value = requestContext.getProperty(configuration.getParameterName());
        return value == null ? null : value.toString();
    }
}

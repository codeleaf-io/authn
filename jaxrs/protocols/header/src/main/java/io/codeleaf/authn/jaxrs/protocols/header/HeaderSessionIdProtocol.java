package io.codeleaf.authn.jaxrs.protocols.header;

import io.codeleaf.authn.jaxrs.spi.JaxrsSessionIdProtocol;

import javax.ws.rs.core.Response;

public final class HeaderSessionIdProtocol implements JaxrsSessionIdProtocol {

    private final HeaderSessionIdConfiguration configuration;

    public HeaderSessionIdProtocol(HeaderSessionIdConfiguration configuration) {
        this.configuration = configuration;
    }

    @Override
    public void setSessionId(Response response, String sessionId) {
        response.getHeaders().add(configuration.getHeaderName(), sessionId);
    }
}

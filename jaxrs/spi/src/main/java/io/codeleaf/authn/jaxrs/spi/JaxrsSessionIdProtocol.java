package io.codeleaf.authn.jaxrs.spi;

import javax.ws.rs.core.Response;

public interface JaxrsSessionIdProtocol {

    void setSessionId(Response response, String sessionId);
}

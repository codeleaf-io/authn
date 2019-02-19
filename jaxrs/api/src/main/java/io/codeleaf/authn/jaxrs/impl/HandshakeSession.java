package io.codeleaf.authn.jaxrs.impl;

import io.codeleaf.authn.jaxrs.spi.HandshakeState;

import javax.ws.rs.container.ContainerRequestContext;
import java.util.Map;

public interface HandshakeSession {

    interface SessionAware {

        void init(HandshakeSession session);
    }

    HandshakeState getState();

    JaxrsRequestAuthenticatorExecutor getExecutor();

    ContainerRequestContext getRequestContext();

    Map<String, Object> getAttributes();
}

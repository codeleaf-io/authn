package io.codeleaf.authn.jaxrs.impl;

import io.codeleaf.authn.jaxrs.HandshakeConfiguration;

import javax.ws.rs.container.ContainerRequestContext;
import javax.ws.rs.core.Response;
import java.util.Objects;

public final class HandshakeStateHandler {

    private final HandshakeConfiguration configuration;

    public HandshakeStateHandler(HandshakeConfiguration configuration) {
        this.configuration = configuration;
    }

    public void setHandshakeState(ContainerRequestContext containerRequestContext, HandshakeState handshakeState) {
        containerRequestContext.setProperty("handshakeState", handshakeState);
    }

    public void setHandshakeState(ContainerRequestContext containerRequestContext, Response.ResponseBuilder responseBuilder, HandshakeState handshakeState) {
        Objects.requireNonNull(handshakeState);
        String sessionData = handshakeState.encode();
        String sessionId = configuration.getStore().storeSessionData(sessionData);
        configuration.getProtocol().setSessionId(containerRequestContext, responseBuilder, sessionId);
    }

    public HandshakeState getHandshakeState(ContainerRequestContext containerRequestContext) {
        return (HandshakeState) containerRequestContext.getProperty("handshakeState");
    }

    public HandshakeState extractHandshakeState(ContainerRequestContext containerRequestContext) {
        String sessionId = configuration.getProtocol().getSessionId(containerRequestContext);
        if (sessionId != null) {
            String sessionData = configuration.getStore().retrieveSessionData(sessionId);
            if (sessionData != null) {
                return HandshakeState.decode(sessionData);
            }
        }
        return null;
    }
}

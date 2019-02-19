package io.codeleaf.authn.jaxrs.impl;

import io.codeleaf.authn.jaxrs.HandshakeConfiguration;

import javax.ws.rs.container.ContainerRequestContext;
import javax.ws.rs.core.PathSegment;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.UriInfo;
import java.net.URI;
import java.util.List;
import java.util.Objects;

public final class HandshakeStateHandler {

    private final HandshakeConfiguration configuration;

    public HandshakeStateHandler(HandshakeConfiguration configuration) {
        this.configuration = configuration;
    }

    public HandshakeConfiguration getConfiguration() {
        return configuration;
    }

    public String getPath() {
        return configuration.getPath();
    }

    public void setHandshakeState(ContainerRequestContext containerRequestContext, Response.ResponseBuilder responseBuilder, HandshakeState handshakeState) {
        Objects.requireNonNull(handshakeState);
        String sessionData = handshakeState.encode();
        String sessionId = configuration.getStore().storeSessionData(sessionData);
        configuration.getProtocol().setSessionId(containerRequestContext, responseBuilder, sessionId);
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

    public Response clearHandshakeState(ContainerRequestContext requestContext) {
        Response response;
        HandshakeState handshakeState = extractHandshakeState(requestContext);
        if (handshakeState != null) {
            Response.ResponseBuilder builder = Response.temporaryRedirect(requestContext.getUriInfo().getRequestUri());
            configuration.getProtocol().clearSessionId(requestContext, builder);
            response = builder.build();
        } else {
            response = null;
        }
        return response;
    }

    public boolean isHandshakePath(URI uri) {
        String[] segments = uri.toString().split("/");
        return segments.length > 0 && Objects.equals(segments[0], getPath().replace("/", ""));
    }

    public boolean isHandshakePath(UriInfo uriInfo) {
        List<PathSegment> segments = uriInfo.getPathSegments();
        return segments.size() > 0 && segments.get(0).getPath().equals(getPath().replace("/", ""));
    }
}

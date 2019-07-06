package io.codeleaf.authn.jaxrs.impl;

import io.codeleaf.authn.AuthenticationContext;
import io.codeleaf.authn.AuthenticationException;
import io.codeleaf.authn.jaxrs.spi.HandshakeState;
import io.codeleaf.authn.jaxrs.spi.JaxrsRequestAuthenticator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.ws.rs.container.ContainerRequestContext;
import javax.ws.rs.container.ContainerResponseContext;
import javax.ws.rs.core.Response;
import java.net.URI;
import java.util.List;

public class JaxrsRequestAuthenticatorExecutor {

    private static final Logger LOGGER = LoggerFactory.getLogger(JaxrsRequestAuthenticatorExecutor.class);

    private final String authenticatorName;
    private final JaxrsRequestAuthenticator authenticator;
    private final HandshakeStateHandler handshakeStateHandler;
    private JaxrsRequestAuthenticatorExecutor parent;
    private JaxrsRequestAuthenticatorExecutor onFailure;
    private AuthenticationContext authenticationContext;

    JaxrsRequestAuthenticatorExecutor(String authenticatorName, JaxrsRequestAuthenticator authenticator, HandshakeStateHandler handshakeStateHandler, JaxrsRequestAuthenticatorExecutor parent) {
        this.authenticatorName = authenticatorName;
        this.authenticator = authenticator;
        this.handshakeStateHandler = handshakeStateHandler;
        this.parent = parent;
    }

    public String getAuthenticatorName() {
        return authenticatorName;
    }

    public JaxrsRequestAuthenticator getAuthenticator() {
        return authenticator;
    }

    public URI getAuthenticatorUri() {
        return URI.create(handshakeStateHandler.getPath() + "/" + HtmlUtil.urlEncode(authenticatorName));
    }

    public HandshakeStateHandler getHandshakeStateHandler() {
        return handshakeStateHandler;
    }

    public JaxrsRequestAuthenticatorExecutor getOnFailure() {
        return onFailure;
    }

    public Response authenticate(ContainerRequestContext requestContext) throws AuthenticationException {
        Response response;
        HandshakeState state = (HandshakeState) requestContext.getProperty("handshakeState");
        List<String> authenticatorNames = state.getAuthenticatorNames();
        authenticatorNames.add(authenticatorName);
        LOGGER.debug("Calling authenticate() on " + authenticator.getClass().getCanonicalName() + "...");
        HandshakeSessionManager.get().setExecutor(this);
        authenticationContext = authenticator.authenticate(requestContext);
        if (authenticationContext != null) {
            LOGGER.debug("Proceeding to parent: " + parent.authenticator.getClass().getCanonicalName() + "...");
            authenticatorNames.remove(authenticatorNames.size() - 1);
            response = parent.onFailureCompleted(requestContext, authenticationContext);
        } else {
            LOGGER.debug("Calling onNotAuthenticated() on " + authenticator.getClass().getCanonicalName() + "...");
            Response.ResponseBuilder responseBuilder = authenticator.onNotAuthenticated(requestContext);
            if (responseBuilder != null) {
                response = buildResponse(requestContext, responseBuilder);
            } else if (onFailure != null) {
                LOGGER.debug("Proceeding to onFailure: " + onFailure.authenticator.getClass().getCanonicalName() + "...");
                response = onFailure.authenticate(requestContext);
            } else {
                response = null;
            }
        }
        return response;
    }

    public Response onFailureCompleted(ContainerRequestContext requestContext, AuthenticationContext authenticationContext) {
        Response response;
        LOGGER.debug("Calling onFailureCompleted() on " + authenticator.getClass().getCanonicalName() + "...");
        HandshakeSessionManager.get().setExecutor(this);
        Response.ResponseBuilder responseBuilder = authenticator.onFailureCompleted(requestContext, authenticationContext);
        if (responseBuilder != null) {
            response = buildResponse(requestContext, responseBuilder);
        } else {
            HandshakeState state = (HandshakeState) requestContext.getProperty("handshakeState");
            List<String> authenticatorNames = state.getAuthenticatorNames();
            LOGGER.debug("Proceeding to parent: " + parent.authenticator.getClass().getCanonicalName() + "...");
            authenticatorNames.remove(authenticatorNames.size() - 1);
            response = parent.onFailureCompleted(requestContext, authenticationContext);
        }
        return response;
    }

    public void onServiceCompleted(ContainerRequestContext containerRequestContext, ContainerResponseContext containerResponseContext) {
        LOGGER.debug("Calling onServiceCompleted() on " + authenticator.getClass().getCanonicalName() + "...");
        HandshakeSessionManager.get().setExecutor(this);
        authenticator.onServiceCompleted(containerRequestContext, containerResponseContext, authenticationContext);
    }

    public void setOnFailure(String authenticatorName, JaxrsRequestAuthenticator authenticator) {
        onFailure = new JaxrsRequestAuthenticatorExecutor(authenticatorName, authenticator, handshakeStateHandler, this);
    }

    public JaxrsRequestAuthenticator getParent() {
        return parent.getAuthenticator();
    }

    public JaxrsRequestAuthenticatorExecutor getParentExecutor() {
        return parent;
    }

    private Response buildResponse(ContainerRequestContext requestContext, Response.ResponseBuilder responseBuilder) {
        HandshakeState state = (HandshakeState) requestContext.getProperty("handshakeState");
        LOGGER.debug("Building response with handshake state: " + state.getAuthenticatorNames());
        handshakeStateHandler.setHandshakeState(requestContext, responseBuilder, state);
        return responseBuilder.build();
    }
}

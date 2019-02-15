package io.codeleaf.authn.jaxrs.impl;

import io.codeleaf.authn.AuthenticationContext;
import io.codeleaf.authn.AuthenticationException;
import io.codeleaf.authn.jaxrs.spi.JaxrsRequestAuthenticator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.ws.rs.container.ContainerRequestContext;
import javax.ws.rs.container.ContainerResponseContext;
import javax.ws.rs.core.Response;
import java.util.List;

public class JaxrsRequestAuthenticatorExecutor implements JaxrsRequestAuthenticator.AuthenticatorContext {

    private static final Logger LOGGER = LoggerFactory.getLogger(JaxrsRequestAuthenticatorExecutor.class);

    private final String authenticatorName;
    private final JaxrsRequestAuthenticator authenticator;
    private final HandshakeStateHandler handshakeStateHandler;
    private JaxrsRequestAuthenticatorExecutor parent;
    private JaxrsRequestAuthenticatorExecutor onFailure;
    private AuthenticationContext authenticationContext;

    public JaxrsRequestAuthenticatorExecutor(String authenticatorName, JaxrsRequestAuthenticator authenticator, HandshakeStateHandler handshakeStateHandler, JaxrsRequestAuthenticatorExecutor parent) {
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

    public HandshakeStateHandler getHandshakeStateHandler() {
        return handshakeStateHandler;
    }

    public JaxrsRequestAuthenticatorExecutor getOnFailure() {
        return onFailure;
    }

    public Response authenticate(ContainerRequestContext requestContext) throws AuthenticationException {
        Response response;
        List<String> authenticatorNames = handshakeStateHandler.getHandshakeState(requestContext).getAuthenticatorNames();
        authenticatorNames.add(authenticatorName);
        LOGGER.debug("Calling authenticate() on " + authenticator.getClass().getCanonicalName() + "...");
        authenticationContext = authenticator.authenticate(requestContext, this);
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
        Response.ResponseBuilder responseBuilder = authenticator.onFailureCompleted(requestContext, authenticationContext);
        if (responseBuilder != null) {
            response = buildResponse(requestContext, responseBuilder);
        } else {
            List<String> authenticatorNames = handshakeStateHandler.getHandshakeState(requestContext).getAuthenticatorNames();
            LOGGER.debug("Proceeding to parent: " + parent.authenticator.getClass().getCanonicalName() + "...");
            authenticatorNames.remove(authenticatorNames.size() - 1);
            response = parent.onFailureCompleted(requestContext, authenticationContext);
        }
        return response;
    }

    public void onServiceCompleted(ContainerRequestContext containerRequestContext, ContainerResponseContext containerResponseContext) {
        LOGGER.debug("Calling onServiceCompleted() on " + authenticator.getClass().getCanonicalName() + "...");
        authenticator.onServiceCompleted(containerRequestContext, containerResponseContext, authenticationContext, this);
    }

    @Override
    public void setOnFailure(String authenticatorName, JaxrsRequestAuthenticator authenticator) {
        onFailure = new JaxrsRequestAuthenticatorExecutor(authenticatorName, authenticator, handshakeStateHandler, this);
    }

    @Override
    public JaxrsRequestAuthenticator getParent() {
        return parent.getAuthenticator();
    }

    private Response buildResponse(ContainerRequestContext containerRequestContext, Response.ResponseBuilder responseBuilder) {
        HandshakeState handshakeState = handshakeStateHandler.getHandshakeState(containerRequestContext);
        LOGGER.debug("Building response with handshake state: " + handshakeState.getAuthenticatorNames());
        handshakeStateHandler.setHandshakeState(containerRequestContext, responseBuilder, handshakeState);
        return responseBuilder.build();
    }
}

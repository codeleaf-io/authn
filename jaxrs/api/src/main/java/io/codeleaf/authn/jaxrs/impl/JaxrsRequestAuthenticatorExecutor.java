package io.codeleaf.authn.jaxrs.impl;

import io.codeleaf.authn.AuthenticationContext;
import io.codeleaf.authn.AuthenticationException;
import io.codeleaf.authn.jaxrs.spi.JaxrsRequestAuthenticator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.ws.rs.container.ContainerRequestContext;
import javax.ws.rs.core.Response;

public class JaxrsRequestAuthenticatorExecutor implements JaxrsRequestAuthenticator.AuthenticatorContext {

    private static final Logger LOGGER = LoggerFactory.getLogger(JaxrsRequestAuthenticatorExecutor.class);

    private final JaxrsRequestAuthenticator authenticator;
    private JaxrsRequestAuthenticatorExecutor parent;
    private JaxrsRequestAuthenticatorExecutor onFailure;

    public JaxrsRequestAuthenticatorExecutor(JaxrsRequestAuthenticator authenticator, JaxrsRequestAuthenticatorExecutor parent) {
        this.authenticator = authenticator;
        this.parent = parent;
    }

    public JaxrsRequestAuthenticator getAuthenticator() {
        return authenticator;
    }

    public JaxrsRequestAuthenticatorExecutor getOnFailure() {
        return onFailure;
    }

    public Response authenticate(ContainerRequestContext requestContext) throws AuthenticationException {
        Response response;
        AuthenticationContext authenticationContext = authenticator.authenticate(requestContext, this);
        if (authenticationContext != null) {
            response = parent.onFailureCompleted(requestContext, authenticationContext);
        } else {
            Response.ResponseBuilder responseBuilder = authenticator.onNotAuthenticated(requestContext);
            if (responseBuilder != null) {
                addHandshakeState(responseBuilder);
                response = responseBuilder.build();
            } else if (onFailure != null) {
                response = onFailure.authenticate(requestContext);
            } else {
                response = null;
            }
        }
        return response;
    }

    public Response onFailureCompleted(ContainerRequestContext requestContext, AuthenticationContext authenticationContext) {
        Response response;
        Response.ResponseBuilder responseBuilder = authenticator.onFailureCompleted(requestContext, authenticationContext);
        if (responseBuilder != null) {
            addHandshakeState(responseBuilder);
            response = responseBuilder.build();
        } else {
            response = parent.onFailureCompleted(requestContext, authenticationContext);
        }
        return response;
    }

    private void addHandshakeState(Response.ResponseBuilder responseBuilder) {
        // TODO: implement
    }

    @Override
    public void setOnFailure(JaxrsRequestAuthenticator authenticator) {
        onFailure = new JaxrsRequestAuthenticatorExecutor(authenticator, this);
    }

    @Override
    public JaxrsRequestAuthenticator getParent() {
        return parent.getAuthenticator();
    }
}

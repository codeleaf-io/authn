package io.codeleaf.authn.jaxrs.impl;

import io.codeleaf.authn.impl.AuthenticatorRegistry;
import io.codeleaf.authn.impl.ThreadLocalAuthenticationContextManager;
import io.codeleaf.authn.jaxrs.spi.JaxrsRequestAuthenticator;

import javax.ws.rs.container.ContainerRequestContext;
import javax.ws.rs.container.ContainerResponseContext;
import javax.ws.rs.container.ContainerResponseFilter;

public final class ZoneHandlerPostServiceFilter implements ContainerResponseFilter {

    private final ThreadLocalAuthenticationContextManager authenticationContextManager;

    public ZoneHandlerPostServiceFilter(ThreadLocalAuthenticationContextManager authenticationContextManager) {
        this.authenticationContextManager = authenticationContextManager;
    }

    @Override
    public void filter(ContainerRequestContext containerRequestContext, ContainerResponseContext containerResponseContext) {
        HandshakeState handshakeState = (HandshakeState) containerRequestContext.getProperty("handshakeState");
        if (handshakeState != null && !handshakeState.getAuthenticatorNames().isEmpty()) {
            // TODO: implement correct - probably need the AuthenticatorExecutor... we could pass as requestContext.getProperty...
            AuthenticatorRegistry.lookup(handshakeState.getAuthenticatorNames().get(0), JaxrsRequestAuthenticator.class).onServiceCompleted(containerRequestContext, containerResponseContext, null, null);
        }
        authenticationContextManager.clearAuthenticationContext();
    }
}

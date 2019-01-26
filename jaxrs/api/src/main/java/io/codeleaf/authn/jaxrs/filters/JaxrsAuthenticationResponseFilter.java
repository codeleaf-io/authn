package io.codeleaf.authn.jaxrs.filters;

import io.codeleaf.authn.impl.ThreadLocalAuthenticationContextManager;

import javax.ws.rs.container.ContainerRequestContext;
import javax.ws.rs.container.ContainerResponseContext;
import javax.ws.rs.container.ContainerResponseFilter;
import java.io.IOException;

public final class JaxrsAuthenticationResponseFilter implements ContainerResponseFilter {

    private final ThreadLocalAuthenticationContextManager authenticationContextManager;

    public JaxrsAuthenticationResponseFilter(ThreadLocalAuthenticationContextManager authenticationContextManager) {
        this.authenticationContextManager = authenticationContextManager;
    }

    @Override
    public void filter(ContainerRequestContext containerRequestContext, ContainerResponseContext containerResponseContext) {
        authenticationContextManager.clearAuthenticationContext();
    }
}

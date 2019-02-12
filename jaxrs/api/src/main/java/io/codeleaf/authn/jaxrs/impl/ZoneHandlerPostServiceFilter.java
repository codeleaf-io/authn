package io.codeleaf.authn.jaxrs.impl;

import javax.ws.rs.container.ContainerRequestContext;
import javax.ws.rs.container.ContainerResponseContext;
import javax.ws.rs.container.ContainerResponseFilter;

public final class ZoneHandlerPostServiceFilter implements ContainerResponseFilter {

    @Override
    public void filter(ContainerRequestContext containerRequestContext, ContainerResponseContext containerResponseContext) {
        JaxrsRequestAuthenticatorExecutor rootExecutor = (JaxrsRequestAuthenticatorExecutor) containerRequestContext.getProperty("authenticatorStack");
        if (rootExecutor != null) {
            rootExecutor.onServiceCompleted(containerRequestContext, containerResponseContext);
        }
    }
}

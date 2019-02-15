package io.codeleaf.authn.jaxrs.impl;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.ws.rs.container.ContainerRequestContext;
import javax.ws.rs.container.ContainerResponseContext;
import javax.ws.rs.container.ContainerResponseFilter;

public final class ZoneHandlerPostServiceFilter implements ContainerResponseFilter {

    private static final Logger LOGGER = LoggerFactory.getLogger(ZoneHandlerPreServiceFilter.class);

    @Override
    public void filter(ContainerRequestContext containerRequestContext, ContainerResponseContext containerResponseContext) {
        if (!(Boolean) containerRequestContext.getProperty("aborted")) {
            JaxrsRequestAuthenticatorExecutor rootExecutor = (JaxrsRequestAuthenticatorExecutor) containerRequestContext.getProperty("authenticatorStack");
            if (rootExecutor != null) {
                rootExecutor.onServiceCompleted(containerRequestContext, containerResponseContext);
            }
        }
        LOGGER.debug("Processing finished for: " + containerRequestContext.getUriInfo().getRequestUri());
    }
}

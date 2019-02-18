package io.codeleaf.authn.jaxrs.impl;

import io.codeleaf.authn.AuthenticationContext;
import io.codeleaf.authn.AuthenticationException;
import io.codeleaf.authn.jaxrs.spi.Authenticate;
import io.codeleaf.common.utils.Methods;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.ws.rs.container.ContainerRequestContext;
import javax.ws.rs.container.ContainerResponseContext;
import javax.ws.rs.container.ContainerResponseFilter;
import javax.ws.rs.container.ResourceInfo;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.Response;

public final class ZoneHandlerPostServiceFilter implements ContainerResponseFilter {

    private static final Logger LOGGER = LoggerFactory.getLogger(ZoneHandlerPreServiceFilter.class);

    private final HandshakeStateHandler handshakeStateHandler;

    @Context
    private ResourceInfo resourceInfo;

    public ZoneHandlerPostServiceFilter(HandshakeStateHandler handshakeStateHandler) {
        this.handshakeStateHandler = handshakeStateHandler;
    }

    @Override
    public void filter(ContainerRequestContext containerRequestContext, ContainerResponseContext containerResponseContext) {
        try {
            Boolean aborted = (Boolean) containerRequestContext.getProperty("aborted");
            if (aborted != null && !aborted) {
                JaxrsRequestAuthenticatorExecutor rootExecutor = (JaxrsRequestAuthenticatorExecutor) containerRequestContext.getProperty("authenticatorStack");
                if (rootExecutor != null) {
                    rootExecutor.onServiceCompleted(containerRequestContext, containerResponseContext);
                }
            } else {
                if (resourceInfo == null || resourceInfo.getResourceMethod() == null) {
                    LOGGER.warn("ResourceMethod is null, resource is: " + resourceInfo);
                } else {
                    if (Methods.hasAnnotation(resourceInfo.getResourceMethod(), Authenticate.class)) {
                        Object entity = containerResponseContext.getEntity();
                        Response response;
                        if (entity == null) {
                            response = handshakeStateHandler.getExecutor(containerRequestContext).getOnFailure().authenticate(containerRequestContext);
                        } else if (entity instanceof AuthenticationContext) {
                            AuthenticationContext authenticationContext = (AuthenticationContext) entity;
                            response = handshakeStateHandler.getExecutor(containerRequestContext).getParentExecutor().onFailureCompleted(containerRequestContext, authenticationContext);
                        } else {
                            LOGGER.error("Invalid return type from @Authenticate resource: " + entity.getClass());
                            response = Response.serverError().build();
                        }
                        containerRequestContext.abortWith(response);
                    }
                }
            }
            Boolean performHandshake = (Boolean) containerRequestContext.getProperty("performHandshake");
            if (performHandshake != null && performHandshake) {
                LOGGER.debug("Sending handshake response for: " + containerRequestContext.getUriInfo().getRequestUri());
            } else {
                LOGGER.debug("Processing finished for: " + containerRequestContext.getUriInfo().getRequestUri());
            }
        } catch (AuthenticationException cause) {
            LOGGER.error("AuthenticationException: " + cause.getMessage());
            containerResponseContext.setStatus(Response.Status.INTERNAL_SERVER_ERROR.getStatusCode());
            containerResponseContext.setEntity(null);
        }
    }
}

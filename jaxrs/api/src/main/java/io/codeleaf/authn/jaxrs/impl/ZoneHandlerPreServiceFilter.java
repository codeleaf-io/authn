package io.codeleaf.authn.jaxrs.impl;

import io.codeleaf.authn.AuthenticationContext;
import io.codeleaf.authn.AuthenticationException;
import io.codeleaf.authn.impl.AuthenticatorRegistry;
import io.codeleaf.authn.impl.ThreadLocalAuthenticationContextManager;
import io.codeleaf.authn.jaxrs.Authentication;
import io.codeleaf.authn.jaxrs.AuthenticationConfiguration;
import io.codeleaf.authn.jaxrs.AuthenticationPolicy;
import io.codeleaf.authn.jaxrs.spi.JaxrsRequestAuthenticator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.ws.rs.container.ContainerRequestContext;
import javax.ws.rs.container.ContainerRequestFilter;
import javax.ws.rs.container.ResourceInfo;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.PathSegment;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.UriInfo;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public final class ZoneHandlerPreServiceFilter implements ContainerRequestFilter {

    private static final Logger LOGGER = LoggerFactory.getLogger(ZoneHandlerPreServiceFilter.class);
    private static final Response UNAUTHORIZED = Response.status(Response.Status.UNAUTHORIZED).build();
    private static final Response SERVER_ERROR = Response.serverError().build();

    private final ThreadLocalAuthenticationContextManager authenticationContextManager;
    private final AuthenticationConfiguration configuration;
    private final HandshakeStateHandler handshakeStateHandler;

    @Context
    private ResourceInfo resourceInfo;

    @Context
    private UriInfo uriInfo;

    public ZoneHandlerPreServiceFilter(ThreadLocalAuthenticationContextManager authenticationContextManager, AuthenticationConfiguration configuration, HandshakeStateHandler handshakeStateHandler) {
        this.authenticationContextManager = authenticationContextManager;
        this.configuration = configuration;
        this.handshakeStateHandler = handshakeStateHandler;
    }

    @Override
    public void filter(ContainerRequestContext containerRequestContext) {
        try {
            LOGGER.debug("Processing request for endpoint: " + uriInfo.getRequestUri());
            Authentication authentication = Authentications.getAuthentication(resourceInfo);
            if (authentication != null) {
                LOGGER.debug("We found an authentication annotation: " + authentication);
            }
            AuthenticationConfiguration.Zone zone = Zones.getZone(uriInfo.getPath(), configuration);
            if (zone != null) {
                LOGGER.debug(String.format("Zone matched: '%s' for: %s", zone.getName(), uriInfo.getPath()));
            }
            AuthenticationPolicy policy = determinePolicy(authentication, zone);
            String authenticatorName = determineAuthenticatorName(authentication, zone);
            handshakeStateHandler.setHandshakeState(containerRequestContext);
            setAuthenticatorExecutorStack(containerRequestContext, authenticatorName);
            switch (policy) {
                case NONE:
                    handleNonePolicy(containerRequestContext);
                    break;
                case OPTIONAL:
                    handleOptionalPolicy(containerRequestContext);
                    break;
                case REQUIRED:
                    handleRequiredPolicy(containerRequestContext);
                    break;
                default:
                    String message = "Aborting request because we have invalid authentication policy!";
                    LOGGER.error(message);
                    throw new IllegalStateException(message);
            }
        } catch (IllegalStateException | IllegalArgumentException | AuthenticationException cause) {
            containerRequestContext.abortWith(SERVER_ERROR);
        }
    }

    private void setAuthenticatorExecutorStack(ContainerRequestContext containerRequestContext, String authenticatorName) {
        JaxrsRequestAuthenticatorExecutor root = new RootRequestAuthenticatorExecutor(authenticationContextManager, handshakeStateHandler);
        JaxrsRequestAuthenticatorExecutor current = root;
        Map<String, JaxrsRequestAuthenticatorExecutor> executorIndex = new HashMap<>();
        while (authenticatorName != null) {
            current.setOnFailure(authenticatorName, AuthenticatorRegistry.lookup(authenticatorName, JaxrsRequestAuthenticator.class));
            current = current.getOnFailure();
            executorIndex.put(authenticatorName, current);
            authenticatorName = configuration.getAuthenticators().get(authenticatorName).getOnFailure();
        }
        containerRequestContext.setProperty("authenticatorStack", root);
        containerRequestContext.setProperty("executorIndex", executorIndex);
    }

    private AuthenticationPolicy determinePolicy(Authentication authentication, AuthenticationConfiguration.Zone zone) {
        return isHandshakePath()
                ? AuthenticationPolicy.NONE
                : authentication != null
                ? authentication.value()
                : zone != null
                ? zone.getPolicy()
                : AuthenticationPolicy.OPTIONAL;
    }

    private boolean isHandshakePath() {
        List<PathSegment> segments = uriInfo.getPathSegments();
        return segments.size() > 0 && segments.get(0).getPath().equals(handshakeStateHandler.getPath().replace("/", ""));
    }

    private String determineAuthenticatorName(Authentication authentication, AuthenticationConfiguration.Zone zone) {
        return authentication != null && !authentication.authenticator().isEmpty()
                ? authentication.authenticator()
                : zone != null && zone.getAuthenticator() != null
                ? zone.getAuthenticator().getName()
                : "default";
    }

    private void handleNonePolicy(ContainerRequestContext containerRequestContext) {
        LOGGER.debug("Policy is NONE; skipping authentication");
    }

    private void handleOptionalPolicy(ContainerRequestContext containerRequestContext) throws AuthenticationException {
        Response response = handshakeStateHandler.getExecutor(containerRequestContext).authenticate(containerRequestContext);
        if (response != null) {
            handleHandshakeInProgress(containerRequestContext, response);
        } else {
            LOGGER.debug("Handshake completed");
            LOGGER.debug("Policy is OPTIONAL, we are " + (!AuthenticationContext.isAuthenticated() ? "NOT " : "") + "authenticated");
        }
    }

    private void handleRequiredPolicy(ContainerRequestContext containerRequestContext) throws AuthenticationException {
        Response response = handshakeStateHandler.getExecutor(containerRequestContext).authenticate(containerRequestContext);
        if (response != null) {
            handleHandshakeInProgress(containerRequestContext, response);
        } else {
            if (AuthenticationContext.isAuthenticated()) {
                LOGGER.debug("Handshake completed");
                LOGGER.debug("Policy is REQUIRED, we are authenticated");
            } else {
                LOGGER.warn("Policy is REQUIRED, we are NOT authenticated; aborting request");
                containerRequestContext.abortWith(UNAUTHORIZED);
            }
        }
    }

    private void handleHandshakeInProgress(ContainerRequestContext containerRequestContext, Response response) {
        containerRequestContext.abortWith(response);
        containerRequestContext.setProperty("aborted", true);
        containerRequestContext.setProperty("performHandshake", true);
    }
}

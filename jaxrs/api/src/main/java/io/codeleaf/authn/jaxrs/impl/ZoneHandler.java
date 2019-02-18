package io.codeleaf.authn.jaxrs.impl;

import io.codeleaf.authn.AuthenticationContext;
import io.codeleaf.authn.AuthenticationException;
import io.codeleaf.authn.impl.AuthenticatorRegistry;
import io.codeleaf.authn.impl.ThreadLocalAuthenticationContextManager;
import io.codeleaf.authn.jaxrs.Authentication;
import io.codeleaf.authn.jaxrs.AuthenticationConfiguration;
import io.codeleaf.authn.jaxrs.AuthenticationPolicy;
import io.codeleaf.authn.jaxrs.spi.Authenticate;
import io.codeleaf.authn.jaxrs.spi.JaxrsRequestAuthenticator;
import io.codeleaf.common.utils.Methods;
import io.codeleaf.common.utils.Types;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.ws.rs.container.*;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.PathSegment;
import javax.ws.rs.core.Response;
import java.net.URI;
import java.util.*;

// TODO: clean up this file
public final class ZoneHandler {

    private static final Logger LOGGER = LoggerFactory.getLogger(ZoneHandler.class);
    private static final Response UNAUTHORIZED = Response.status(Response.Status.UNAUTHORIZED).build();
    private static final Response SERVER_ERROR = Response.serverError().build();

    private final ThreadLocalAuthenticationContextManager authenticationContextManager;
    private final AuthenticationConfiguration configuration;
    private final HandshakeStateHandler handshakeStateHandler;

    private final Set<Object> filters = Collections.unmodifiableSet(new LinkedHashSet<>(Arrays.asList(
            new PreMatchingFilter(), new PreResourceFilter(), new PostResourceFilter()
    )));

    public ZoneHandler(ThreadLocalAuthenticationContextManager authenticationContextManager, AuthenticationConfiguration configuration, HandshakeStateHandler handshakeStateHandler) {
        this.authenticationContextManager = authenticationContextManager;
        this.configuration = configuration;
        this.handshakeStateHandler = handshakeStateHandler;
    }

    public Set<Object> getFilters() {
        return filters;
    }

    @PreMatching
    public final class PreMatchingFilter implements ContainerRequestFilter {

        @Override
        public void filter(ContainerRequestContext requestContext) {
            URI requestUri = requestContext.getUriInfo().getRequestUri();
            LOGGER.debug("Processing request for endpoint: " + requestUri);
            if (hasHandshakePath(requestContext)) {
                requestContext.setProperty("handshakeResource", true);
            }
            HandshakeState state = handshakeStateHandler.extractHandshakeState(requestContext);
            if (state != null) {
                requestContext.setProperty("handshakeState", state);
            }
        }
    }

    public final class PreResourceFilter implements ContainerRequestFilter {

        @Context
        private ResourceInfo resourceInfo;

        @Override
        public void filter(ContainerRequestContext requestContext) {
            requestContext.setProperty("matched", true);
            if (Boolean.TRUE.equals(requestContext.getProperty("handshakeResource"))) {
                preHandshakeCall(requestContext, resourceInfo);
            } else {
                preServiceCall(requestContext, resourceInfo);
            }
        }
    }

    public final class PostResourceFilter implements ContainerResponseFilter {

        @Context
        private ResourceInfo resourceInfo;

        @Override
        public void filter(ContainerRequestContext requestContext, ContainerResponseContext responseContext) {
            if (!Boolean.TRUE.equals(requestContext.getProperty("matched"))) {
                LOGGER.warn("Endpoint not matched: " + requestContext.getRequest().getMethod() + " " + requestContext.getUriInfo().getAbsolutePath());
            } else if (Boolean.TRUE.equals(requestContext.getProperty("handshakeResource"))) {
                postHandshakeCall(requestContext, responseContext, resourceInfo);
            } else {
                postServiceCall(requestContext, responseContext);
            }
        }
    }

    private void preHandshakeCall(ContainerRequestContext requestContext, ResourceInfo resourceInfo) {
        try {
            LOGGER.debug("Handshake matched: " + resourceInfo.getResourceClass().getCanonicalName() + "." + resourceInfo.getResourceMethod().getName());
            Authentication authentication = Authentications.getAuthentication(resourceInfo);
            if (authentication != null) {
                LOGGER.debug("We found an authentication annotation: " + authentication);
            }
            AuthenticationPolicy policy = authentication != null ? authentication.value() : AuthenticationPolicy.NONE;
            String authenticatorName = authentication != null && !authentication.authenticator().isEmpty() ? authentication.authenticator() : "default";
            if (requestContext.getProperty("handshakeState") == null) {
                requestContext.setProperty("handshakeState", new HandshakeState(requestContext.getUriInfo().getRequestUri()));
            }
            setAuthenticatorExecutorStack(requestContext, authenticatorName);
            switch (policy) {
                case NONE:
                    handleNonePolicy(requestContext);
                    break;
                case OPTIONAL:
                    handleOptionalPolicy(requestContext);
                    break;
                case REQUIRED:
                    handleRequiredPolicy(requestContext);
                    break;
                default:
                    String message = "Aborting request because we have invalid authentication policy!";
                    LOGGER.error(message);
                    throw new IllegalStateException(message);
            }
        } catch (IllegalStateException | IllegalArgumentException | AuthenticationException cause) {
            requestContext.setProperty("aborted", true);
            requestContext.abortWith(SERVER_ERROR);
        }
    }

    private void preServiceCall(ContainerRequestContext requestContext, ResourceInfo resourceInfo) {
        try {
            LOGGER.debug("Service matched: " + resourceInfo.getResourceClass().getCanonicalName() + "." + resourceInfo.getResourceMethod().getName());
            Authentication authentication = Authentications.getAuthentication(resourceInfo);
            if (authentication != null) {
                LOGGER.debug("We found an authentication annotation: " + authentication);
            }
            AuthenticationConfiguration.Zone zone = Zones.getZone(requestContext.getUriInfo().getPath(), configuration);
            if (zone != null) {
                LOGGER.debug(String.format("Zone matched: '%s' for: %s", zone.getName(), requestContext.getUriInfo().getPath()));
            }
            AuthenticationPolicy policy = determinePolicy(authentication, zone);
            String authenticatorName = determineAuthenticatorName(authentication, zone);
            if (requestContext.getProperty("handshakeState") == null) {
                requestContext.setProperty("handshakeState", new HandshakeState(requestContext.getUriInfo().getRequestUri()));
            }
            setAuthenticatorExecutorStack(requestContext, authenticatorName);
            switch (policy) {
                case NONE:
                    handleNonePolicy(requestContext);
                    break;
                case OPTIONAL:
                    handleOptionalPolicy(requestContext);
                    break;
                case REQUIRED:
                    handleRequiredPolicy(requestContext);
                    break;
                default:
                    String message = "Aborting request because we have invalid authentication policy!";
                    LOGGER.error(message);
                    throw new IllegalStateException(message);
            }
        } catch (IllegalStateException | IllegalArgumentException | AuthenticationException cause) {
            requestContext.setProperty("aborted", true);
            requestContext.abortWith(SERVER_ERROR);
        }
    }

    private void postHandshakeCall(ContainerRequestContext requestContext, ContainerResponseContext responseContext, ResourceInfo resourceInfo) {
        try {
            if (Methods.hasAnnotation(resourceInfo.getResourceMethod(), Authenticate.class)) {
                Object entity = responseContext.getEntity();
                Response response;
                if (entity == null) {
                    response = getExecutor(requestContext).getOnFailure().authenticate(requestContext);
                } else if (entity instanceof AuthenticationContext) {
                    AuthenticationContext authenticationContext = (AuthenticationContext) entity;
                    response = getExecutor(requestContext).getParentExecutor().onFailureCompleted(requestContext, authenticationContext);
                } else {
                    LOGGER.error("Invalid return type from @Authenticate resource: " + entity.getClass());
                    response = Response.serverError().build();
                }
                requestContext.setProperty("aborted", true);
                requestContext.abortWith(response);
            }
        } catch (AuthenticationException cause) {
            requestContext.setProperty("aborted", true);
            requestContext.abortWith(SERVER_ERROR);
        }
    }

    private void postServiceCall(ContainerRequestContext requestContext, ContainerResponseContext responseContext) {
        if (Boolean.TRUE.equals(requestContext.getProperty("aborted"))) {
            if (Boolean.TRUE.equals(requestContext.getProperty("performHandshake"))) {
                LOGGER.debug("Sending handshake response for: " + requestContext.getUriInfo().getRequestUri());
            } else {
                LOGGER.debug("Aborting request with " + responseContext.getStatus() + " for: " + requestContext.getUriInfo().getRequestUri());
            }
        } else {
            JaxrsRequestAuthenticatorExecutor rootExecutor = (JaxrsRequestAuthenticatorExecutor) requestContext.getProperty("authenticatorStack");
            if (rootExecutor != null) {
                rootExecutor.onServiceCompleted(requestContext, responseContext);
            }
            LOGGER.debug("Processing finished for: " + requestContext.getUriInfo().getRequestUri());
        }
    }

    private AuthenticationPolicy determinePolicy(Authentication authentication, AuthenticationConfiguration.Zone zone) {
        return authentication != null
                ? authentication.value()
                : zone != null
                ? zone.getPolicy()
                : AuthenticationPolicy.OPTIONAL;
    }

    private boolean hasHandshakePath(ContainerRequestContext requestContext) {
        List<PathSegment> segments = requestContext.getUriInfo().getPathSegments();
        return segments.size() > 0 && segments.get(0).getPath().equals(handshakeStateHandler.getPath().replace("/", ""));
    }

    private String determineAuthenticatorName(Authentication authentication, AuthenticationConfiguration.Zone zone) {
        return authentication != null && !authentication.authenticator().isEmpty()
                ? authentication.authenticator()
                : zone != null && zone.getAuthenticator() != null
                ? zone.getAuthenticator().getName()
                : "default";
    }

    private void handleNonePolicy(ContainerRequestContext requestContext) {
        LOGGER.debug("Policy is NONE; skipping authentication");
    }

    private void handleOptionalPolicy(ContainerRequestContext requestContext) throws AuthenticationException {
        Response response = getExecutor(requestContext).authenticate(requestContext);
        if (response != null) {
            requestContext.setProperty("performHandshake", true);
            requestContext.setProperty("aborted", true);
            requestContext.abortWith(response);
        } else {
            LOGGER.debug("Handshake completed");
            LOGGER.debug("Policy is OPTIONAL, we are " + (!AuthenticationContext.isAuthenticated() ? "NOT " : "") + "authenticated");
        }
    }

    private void handleRequiredPolicy(ContainerRequestContext requestContext) throws AuthenticationException {
        Response response = getExecutor(requestContext).authenticate(requestContext);
        if (response != null) {
            requestContext.setProperty("performHandshake", true);
            requestContext.setProperty("aborted", true);
            requestContext.abortWith(response);
        } else {
            if (AuthenticationContext.isAuthenticated()) {
                LOGGER.debug("Handshake completed");
                LOGGER.debug("Policy is REQUIRED, we are authenticated");
            } else {
                LOGGER.warn("Policy is REQUIRED, we are NOT authenticated; aborting request");
                requestContext.setProperty("aborted", true);
                requestContext.abortWith(UNAUTHORIZED);
            }
        }
    }

    private void setAuthenticatorExecutorStack(ContainerRequestContext requestContext, String authenticatorName) {
        JaxrsRequestAuthenticatorExecutor root = new RootRequestAuthenticatorExecutor(authenticationContextManager, handshakeStateHandler);
        JaxrsRequestAuthenticatorExecutor current = root;
        Map<String, JaxrsRequestAuthenticatorExecutor> executorIndex = new HashMap<>();
        while (authenticatorName != null) {
            current.setOnFailure(authenticatorName, AuthenticatorRegistry.lookup(authenticatorName, JaxrsRequestAuthenticator.class));
            current = current.getOnFailure();
            executorIndex.put(authenticatorName, current);
            authenticatorName = configuration.getAuthenticators().get(authenticatorName).getOnFailure();
        }
        requestContext.setProperty("authenticatorStack", root);
        requestContext.setProperty("executorIndex", executorIndex);
    }

    private JaxrsRequestAuthenticatorExecutor getExecutor(ContainerRequestContext requestContext) {
        JaxrsRequestAuthenticatorExecutor executor;
        HandshakeState state = (HandshakeState) requestContext.getProperty("handshakeState");
        Map<String, JaxrsRequestAuthenticatorExecutor> executorIndex = Types.cast(requestContext.getProperty("executorIndex"));
        if (executorIndex.isEmpty()) {
            if (!state.getAuthenticatorNames().isEmpty()) {
                throw new IllegalArgumentException("Invalid amount of authenticator names found!");
            }
            executor = ((JaxrsRequestAuthenticatorExecutor) requestContext.getProperty("authenticatorStack"));
        } else {
            if (state.getAuthenticatorNames().isEmpty()) {
                executor = ((JaxrsRequestAuthenticatorExecutor) requestContext.getProperty("authenticatorStack"));
            } else {
                executor = executorIndex.get(state.getAuthenticatorNames().get(state.getAuthenticatorNames().size() - 1));
            }
            if (executor == null) {
                throw new IllegalArgumentException("Invalid authenticator name in authentication handshake!");
            }
        }
        System.out.println("getting: " + executor.getAuthenticatorName());
        return executor;
    }
}

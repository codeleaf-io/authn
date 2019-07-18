package io.codeleaf.authn.jaxrs.impl;

import io.codeleaf.authn.AuthenticationContext;
import io.codeleaf.authn.AuthenticationException;
import io.codeleaf.authn.impl.AuthenticatorRegistry;
import io.codeleaf.authn.impl.ThreadLocalAuthenticationContextManager;
import io.codeleaf.authn.jaxrs.Authentication;
import io.codeleaf.authn.jaxrs.AuthenticationConfiguration;
import io.codeleaf.authn.jaxrs.AuthenticationPolicy;
import io.codeleaf.authn.jaxrs.spi.Authenticate;
import io.codeleaf.authn.jaxrs.spi.HandshakeState;
import io.codeleaf.authn.jaxrs.spi.JaxrsRequestAuthenticator;
import io.codeleaf.common.utils.Methods;
import io.codeleaf.common.utils.Types;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.ws.rs.container.*;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.Response;
import java.io.IOException;
import java.net.URI;
import java.util.*;

public final class ZoneHandler {

    private static final Logger LOGGER = LoggerFactory.getLogger(ZoneHandler.class);
    private static final Response UNAUTHORIZED = Response.status(Response.Status.UNAUTHORIZED).build();
    private static final Response SERVER_ERROR = Response.serverError().build();

    private final ThreadLocalAuthenticationContextManager authenticationContextManager;
    private final AuthenticationConfiguration configuration;
    private final HandshakeStateHandler handshakeStateHandler;

    private final CorsFilter corsFilter = new CorsFilter();
    private final Set<Object> filters = Collections.unmodifiableSet(new LinkedHashSet<>(Arrays.asList(
            corsFilter, new PreMatchingFilter(), new PreResourceFilter(), new PostResourceFilter()
    )));

    public ZoneHandler(ThreadLocalAuthenticationContextManager authenticationContextManager, AuthenticationConfiguration configuration, HandshakeStateHandler handshakeStateHandler) {
        this.authenticationContextManager = authenticationContextManager;
        this.configuration = configuration;
        this.handshakeStateHandler = handshakeStateHandler;
        // TODO: set allowed Origins on CorsFilter, after this is available in AuthenticationConfiguration
    }

    public Set<Object> getFilters() {
        return filters;
    }

    @PreMatching
    public final class PreMatchingFilter implements ContainerRequestFilter {

        @Override
        public void filter(ContainerRequestContext requestContext) {
            URI requestUri = requestContext.getUriInfo().getRequestUri();
            LOGGER.debug("Processing request for endpoint: " + requestContext.getMethod() + " " + requestUri);
            HandshakeSessionManager.get().setRequestContext(requestContext);
            if (handshakeStateHandler.isHandshakePath(requestContext.getUriInfo())) {
                setTrue(requestContext, "handshakeResource");
                requestContext.setProperty("authenticator", handshakeStateHandler.getHandshakeAuthenticatorName(requestContext.getUriInfo()));
            }
        }
    }

    public final class PreResourceFilter implements ContainerRequestFilter {

        @Context
        private ResourceInfo resourceInfo;

        @Override
        public void filter(ContainerRequestContext requestContext) {
            try {
                setTrue(requestContext, "matched");
                LOGGER.debug("Resource matched: " + resourceInfo.getResourceClass().getCanonicalName() + "#" + resourceInfo.getResourceMethod().getName());
                HandshakeState state = handshakeStateHandler.extractHandshakeState(requestContext);
                LOGGER.debug("Extracted handshake state: " + (state == null ? "none" : state.getUri() + " " + state.getAuthenticatorNames()));
                if (isTrue(requestContext, "handshakeResource")) {
                    String authenticatorName = (String) requestContext.getProperty("authenticator");
                    if (!AuthenticatorRegistry.contains(authenticatorName, JaxrsRequestAuthenticator.class)) {
                        throw new AuthenticationException();
                    }
                    JaxrsRequestAuthenticator authenticator = AuthenticatorRegistry.lookup(authenticatorName, JaxrsRequestAuthenticator.class);
                    LOGGER.debug("Calling setHandshakeState() on " + authenticator.getClass().getCanonicalName());
                    state = authenticator.setHandshakeState(requestContext, resourceInfo, state);
                    if (state == null) {
                        setTrue(requestContext, "aborted");
                        requestContext.abortWith(Response.status(Response.Status.BAD_REQUEST).build());
                        throw new AuthenticationException("No state set by authenticator!");
                    }
                    setHandshakeState(requestContext, state);
                } else {
                    setHandshakeState(requestContext, state == null ? new HandshakeState(requestContext.getUriInfo().getRequestUri()) : state);
                }
                Authentication authentication = Authentications.getAuthentication(resourceInfo);
                AuthenticationConfiguration.Zone zone = Zones.getZone(requestContext.getUriInfo().getPath(), configuration);
                LOGGER.debug("Configuration: "
                        + "authentication = " + (authentication == null ? "none" : authentication.authenticator() + ":" + authentication.value())
                        + ", zone = " + (zone == null ? "none" : zone.getName()));
                String authenticatorName = determineAuthenticatorName(authentication, zone);
                AuthenticationPolicy policy = determinePolicy(authentication, zone, isTrue(requestContext, "handshakeResource") ? AuthenticationPolicy.NONE : AuthenticationPolicy.OPTIONAL);
                setExecutors(requestContext, authenticatorName);
                handleAuthentication(requestContext, policy);
                if (isTrue(requestContext, "handshakeResource")) {
                    setExecutors(requestContext, state.getFirstAuthenticatorName());
                    HandshakeSessionManager.get().setExecutor(getCurrentExecutor(requestContext));
                }
            } catch (AuthenticationException cause) {
                if (!isTrue(requestContext, "aborted")) {
                    setTrue(requestContext, "aborted");
                    requestContext.abortWith(SERVER_ERROR);
                }
            } catch (IOException cause) {
                if (!isTrue(requestContext, "aborted")) {
                    setTrue(requestContext, "aborted");
                    requestContext.abortWith(Response.status(Response.Status.BAD_REQUEST).build());
                }
            }
        }
    }

    public final class PostResourceFilter implements ContainerResponseFilter {

        @Context
        private ResourceInfo resourceInfo;

        @Override
        public void filter(ContainerRequestContext requestContext, ContainerResponseContext responseContext) {
            try {
                if (!isTrue(requestContext, "matched")) {
                    LOGGER.warn("Endpoint not matched: " + requestContext.getRequest().getMethod() + " " + requestContext.getUriInfo().getAbsolutePath());
                } else if (isTrue(requestContext, "handshakeResource")) {
                    postHandshakeCall(requestContext, responseContext, resourceInfo);
                } else {
                    postServiceCall(requestContext, responseContext);
                }
            } finally {
                HandshakeSessionManager.get().clear();
            }
        }
    }

    private void setExecutors(ContainerRequestContext requestContext, String authenticatorName) {
        JaxrsRequestAuthenticatorExecutor root = new RootRequestAuthenticatorExecutor(authenticationContextManager, handshakeStateHandler);
        JaxrsRequestAuthenticatorExecutor current = root;
        Map<String, JaxrsRequestAuthenticatorExecutor> executorIndex = new HashMap<>();
        while (authenticatorName != null) {
            current.setOnFailure(authenticatorName, AuthenticatorRegistry.lookup(authenticatorName, JaxrsRequestAuthenticator.class));
            current = current.getOnFailure();
            executorIndex.put(authenticatorName, current);
            authenticatorName = configuration.getAuthenticators().get(authenticatorName).getOnFailure();
        }
        requestContext.setProperty("executorRoot", root);
        requestContext.setProperty("executorIndex", executorIndex);
    }

    private RootRequestAuthenticatorExecutor getRootExecutor(ContainerRequestContext requestContext) {
        return (RootRequestAuthenticatorExecutor) requestContext.getProperty("executorRoot");
    }

    private JaxrsRequestAuthenticatorExecutor getCurrentExecutor(ContainerRequestContext requestContext) {
        JaxrsRequestAuthenticatorExecutor executor;
        HandshakeState state = getHandshakeState(requestContext);
        Map<String, JaxrsRequestAuthenticatorExecutor> executorIndex = Types.cast(requestContext.getProperty("executorIndex"));
        if (executorIndex.isEmpty()) {
            if (!state.getAuthenticatorNames().isEmpty()) {
                throw new IllegalArgumentException("Invalid amount of authenticator names found!");
            }
            executor = ((JaxrsRequestAuthenticatorExecutor) requestContext.getProperty("executorRoot"));
        } else {
            String currentAuthenticatorName = state.getLastAuthenticatorName();
            if (currentAuthenticatorName == null) {
                executor = ((JaxrsRequestAuthenticatorExecutor) requestContext.getProperty("executorRoot"));
            } else {
                executor = executorIndex.get(currentAuthenticatorName);
            }
            if (executor == null) {
                throw new IllegalArgumentException("Invalid authenticator name in authentication handshake!");
            }
        }
        LOGGER.debug("Current executor: " + executor.getAuthenticatorName());
        return executor;
    }

    private static AuthenticationPolicy determinePolicy(Authentication authentication, AuthenticationConfiguration.Zone zone, AuthenticationPolicy defaultPolicy) {
        return authentication != null
                ? authentication.value()
                : zone != null
                ? zone.getPolicy()
                : defaultPolicy;
    }

    private static String determineAuthenticatorName(Authentication authentication, AuthenticationConfiguration.Zone zone) {
        return authentication != null && !authentication.authenticator().isEmpty()
                ? authentication.authenticator()
                : zone != null && zone.getAuthenticator() != null
                ? zone.getAuthenticator().getName()
                : "default";
    }

    private void handleAuthentication(ContainerRequestContext requestContext, AuthenticationPolicy policy) {
        try {
            if (policy == AuthenticationPolicy.NONE) {
                LOGGER.debug("Policy is NONE; skipping authentication");
                return;
            }
            if (policy != AuthenticationPolicy.REQUIRED && policy != AuthenticationPolicy.OPTIONAL) {
                LOGGER.error("Unknown policy: " + policy);
                throw new IllegalStateException();
            }
            Response response = getCurrentExecutor(requestContext).authenticate(requestContext);
            if (response != null) {
                requestContext.setProperty("performHandshake", true);
                requestContext.setProperty("aborted", true);
                requestContext.abortWith(response);
            } else {
                boolean authenticated = AuthenticationContext.isAuthenticated();
                LOGGER.debug("Handshake completed");
                LOGGER.debug("Policy is " + policy + ", we are " + (!authenticated ? "NOT " : "") + "authenticated");
                if (policy == AuthenticationPolicy.REQUIRED && !authenticated) {
                    LOGGER.warn("Policy is REQUIRED, we are NOT authenticated; aborting request");
                    requestContext.setProperty("aborted", true);
                    requestContext.abortWith(UNAUTHORIZED);
                }
            }
        } catch (IllegalStateException | IllegalArgumentException | AuthenticationException cause) {
            requestContext.setProperty("aborted", true);
            requestContext.abortWith(SERVER_ERROR);
        }
    }

    private void postHandshakeCall(ContainerRequestContext requestContext, ContainerResponseContext responseContext, ResourceInfo resourceInfo) {
        try {
            if (isTrue(requestContext, "aborted")) {
                LOGGER.debug("Aborting request with " + responseContext.getStatus() + " for: " + requestContext.getUriInfo().getRequestUri());
                return;
            }
            if (Methods.hasAnnotation(resourceInfo.getResourceMethod(), Authenticate.class)) {
                setTrue(requestContext, "@Authenticate");
                Object entity = responseContext.getEntity();
                Response response;
                if (entity == null) {
                    response = getCurrentExecutor(requestContext).getOnFailure().authenticate(requestContext);
                } else if (entity instanceof AuthenticationContext) {
                    List<String> authenticatorNames = getHandshakeState(requestContext).getAuthenticatorNames();
                    authenticatorNames.remove(authenticatorNames.size() - 1);
                    AuthenticationContext authenticationContext = (AuthenticationContext) entity;
                    response = getCurrentExecutor(requestContext).onFailureCompleted(requestContext, authenticationContext);
                } else {
                    LOGGER.error("Invalid return type from @Authenticate resource: " + entity.getClass());
                    response = Response.serverError().build();
                }
                if (response == null) {
                    HandshakeState state = getHandshakeState(requestContext);
                    if (!handshakeStateHandler.isHandshakePath(state.getUri())) {
                        LOGGER.debug("Sending redirect to service...");
                        response = Response.seeOther(state.getUri()).build();
                    } else {
                        LOGGER.debug("Sending no content...");
                        response = Response.noContent().build();
                    }
                } else {
                    LOGGER.debug("Sending authenticator response...");
                }
                replaceResponse(response, responseContext);
            } else {
                LOGGER.debug("Sending authenticator response...");
            }
        } catch (AuthenticationException cause) {
            replaceResponse(SERVER_ERROR, responseContext);
        }
    }

    private void postServiceCall(ContainerRequestContext requestContext, ContainerResponseContext responseContext) {
        if (isTrue(requestContext, "aborted")) {
            if (isTrue(requestContext, "performHandshake")) {
                LOGGER.debug("Sending handshake response for: " + requestContext.getUriInfo().getRequestUri());
                if (responseContext.getStatusInfo().getFamily() == Response.Status.Family.REDIRECTION) {
                    LOGGER.debug("Redirecting to: " + responseContext.getHeaderString("Location"));
                }
            } else {
                LOGGER.debug("Aborting request with " + responseContext.getStatus() + " for: " + requestContext.getUriInfo().getRequestUri());
            }
        } else {
            getRootExecutor(requestContext).onServiceCompleted(requestContext, responseContext);
            LOGGER.debug("Processing finished for: " + requestContext.getUriInfo().getRequestUri());
        }
    }

    private void replaceResponse(Response response, ContainerResponseContext responseContext) {
        responseContext.setStatus(response.getStatus());
        responseContext.getHeaders().clear();
        for (Map.Entry<String, List<Object>> header : response.getHeaders().entrySet()) {
            for (Object value : header.getValue()) {
                responseContext.getHeaders().add(header.getKey(), value);
            }
        }
        responseContext.setEntity(response.getEntity());
    }

    public static void setTrue(ContainerRequestContext requestContext, String propertyName) {
        requestContext.setProperty(propertyName, Boolean.TRUE);
    }

    public static boolean isTrue(ContainerRequestContext requestContext, String propertyName) {
        return Boolean.TRUE.equals(requestContext.getProperty(propertyName));
    }

    public static void setHandshakeState(ContainerRequestContext requestContext, HandshakeState state) {
        state = state == null ? new HandshakeState(requestContext.getUriInfo().getRequestUri()) : state;
        HandshakeSessionManager.get().setState(state);
        requestContext.setProperty("handshakeState", state);
        LOGGER.debug("Handshake state set: " + state.getUri() + " " + state.getAuthenticatorNames());
    }

    public static HandshakeState getHandshakeState(ContainerRequestContext requestContext) {
        HandshakeState state = (HandshakeState) requestContext.getProperty("handshakeState");
        if (state == null) {
            throw new IllegalStateException("No handshake state set!");
        }
        return state;
    }
}

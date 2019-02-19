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
import javax.ws.rs.core.Response;
import java.net.URI;
import java.util.*;

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
            if (handshakeStateHandler.isHandshakePath(requestContext.getUriInfo())) {
                setTrue(requestContext, "handshakeResource");
            }
        }
    }

    public final class PreResourceFilter implements ContainerRequestFilter {

        @Context
        private ResourceInfo resourceInfo;

        @Override
        public void filter(ContainerRequestContext requestContext) {
            setTrue(requestContext, "matched");
            LOGGER.debug("Resource matched: " + resourceInfo.getResourceClass().getCanonicalName() + "#" + resourceInfo.getResourceMethod().getName());
            HandshakeState state = handshakeStateHandler.extractHandshakeState(requestContext);
            LOGGER.debug("Handshake state: " + (state == null ? "none" : state.getUri() + " " + state.getAuthenticatorNames()));
            setHandshakeState(requestContext, state == null ? new HandshakeState(requestContext.getUriInfo().getRequestUri()) : state);
            Authentication authentication = Authentications.getAuthentication(resourceInfo);
            AuthenticationConfiguration.Zone zone = Zones.getZone(requestContext.getUriInfo().getPath(), configuration);
            LOGGER.debug("Configuration: "
                    + "authentication = " + (authentication == null ? "none" : authentication.authenticator() + ":" + authentication.value())
                    + ", zone = " + (zone == null ? "none" : zone.getName()));
            String authenticatorName = determineAuthenticatorName(authentication, zone);
            AuthenticationPolicy policy = determinePolicy(authentication, zone, isTrue(requestContext, "handshakeResource") ? AuthenticationPolicy.NONE : AuthenticationPolicy.OPTIONAL);
            setExecutors(requestContext, authenticatorName);
            handleAuthentication(requestContext, policy);
        }
    }

    public final class PostResourceFilter implements ContainerResponseFilter {

        @Context
        private ResourceInfo resourceInfo;

        @Override
        public void filter(ContainerRequestContext requestContext, ContainerResponseContext responseContext) {
            if (!isTrue(requestContext, "matched")) {
                LOGGER.warn("Endpoint not matched: " + requestContext.getRequest().getMethod() + " " + requestContext.getUriInfo().getAbsolutePath());
            } else if (isTrue(requestContext, "handshakeResource")) {
                postHandshakeCall(requestContext, responseContext, resourceInfo);
            } else {
                postServiceCall(requestContext, responseContext);
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
            if (state.getAuthenticatorNames().isEmpty()) {
                executor = ((JaxrsRequestAuthenticatorExecutor) requestContext.getProperty("executorRoot"));
            } else {
                executor = executorIndex.get(state.getAuthenticatorNames().get(state.getAuthenticatorNames().size() - 1));
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
            if (Methods.hasAnnotation(resourceInfo.getResourceMethod(), Authenticate.class)) {
                Object entity = responseContext.getEntity();
                Response response;
                if (entity == null) {
                    response = getCurrentExecutor(requestContext).getOnFailure().authenticate(requestContext);
                } else if (entity instanceof AuthenticationContext) {
                    AuthenticationContext authenticationContext = (AuthenticationContext) entity;
                    response = getCurrentExecutor(requestContext).getParentExecutor().onFailureCompleted(requestContext, authenticationContext);
                } else {
                    LOGGER.error("Invalid return type from @Authenticate resource: " + entity.getClass());
                    response = Response.serverError().build();
                }
                if (response == null) {
                    HandshakeState state = getHandshakeState(requestContext);
                    if (!handshakeStateHandler.isHandshakePath(state.getUri())) {
                        LOGGER.debug("Sending redirect to service...");
                        response = Response.temporaryRedirect(state.getUri()).build();
                    } else {
                        LOGGER.debug("Sending no content...");
                        response = Response.noContent().build();
                    }
                } else {
                    LOGGER.debug("Sending authenticator response...");
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

    private static void setTrue(ContainerRequestContext requestContext, String propertyName) {
        requestContext.setProperty(propertyName, Boolean.TRUE);
    }

    private static boolean isTrue(ContainerRequestContext requestContext, String propertyName) {
        return Boolean.TRUE.equals(requestContext.getProperty(propertyName));
    }

    private static void setHandshakeState(ContainerRequestContext requestContext, HandshakeState state) {
        requestContext.setProperty("handshakeState", state == null ? new HandshakeState(requestContext.getUriInfo().getRequestUri()) : state);
    }

    private static HandshakeState getHandshakeState(ContainerRequestContext requestContext) {
        HandshakeState state = (HandshakeState) requestContext.getProperty("handshakeState");
        if (state == null) {
            throw new IllegalStateException("No handshake state set!");
        }
        return state;
    }
}

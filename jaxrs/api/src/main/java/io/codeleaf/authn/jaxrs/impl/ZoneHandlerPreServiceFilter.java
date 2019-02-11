package io.codeleaf.authn.jaxrs.impl;

import io.codeleaf.authn.AuthenticationContext;
import io.codeleaf.authn.AuthenticationException;
import io.codeleaf.authn.impl.AuthenticatorRegistry;
import io.codeleaf.authn.impl.ThreadLocalAuthenticationContextManager;
import io.codeleaf.authn.jaxrs.Authentication;
import io.codeleaf.authn.jaxrs.AuthenticationConfiguration;
import io.codeleaf.authn.jaxrs.AuthenticationPolicy;
import io.codeleaf.authn.jaxrs.spi.JaxrsRequestAuthenticator;
import io.codeleaf.config.spec.InvalidSpecificationException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.ws.rs.container.ContainerRequestContext;
import javax.ws.rs.container.ContainerRequestFilter;
import javax.ws.rs.container.ResourceInfo;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.UriInfo;
import java.util.Map;

public final class ZoneHandlerPreServiceFilter implements ContainerRequestFilter {

    private static final Logger LOGGER = LoggerFactory.getLogger(ZoneHandlerPreServiceFilter.class);
    private static final Response UNAUTHORIZED = Response.status(Response.Status.UNAUTHORIZED).build();
    private static final Response SERVER_ERROR = Response.serverError().build();

    private final ThreadLocalAuthenticationContextManager authenticationContextManager;
    private final AuthenticationConfiguration configuration;

    @Context
    private ResourceInfo resourceInfo;

    @Context
    private UriInfo uriInfo;

    public ZoneHandlerPreServiceFilter(ThreadLocalAuthenticationContextManager authenticationContextManager, AuthenticationConfiguration configuration) {
        this.authenticationContextManager = authenticationContextManager;
        this.configuration = configuration;
    }

    @Override
    public void filter(ContainerRequestContext containerRequestContext) {
        LOGGER.debug("Processing request for endpoint: " + uriInfo.getPath());
        Authentication authentication = Authentications.getAuthentication(resourceInfo);
        if (authentication != null) {
            LOGGER.debug("We found an authentication annotation: " + authentication);
        }
        AuthenticationConfiguration.Zone zone = Zones.getZone(uriInfo.getPath(), configuration);
        if (zone != null) {
            LOGGER.debug(String.format("Zone matched: '%s' for: %s", zone.getName(), uriInfo.getPath()));
        }
        AuthenticationPolicy policy = determinePolicy(authentication, zone);
        try {
        setHandshakeState(containerRequestContext, authentication, zone);
        setAuthenticatorExecutorStack(authentication, zone, containerRequestContext);
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
                    LOGGER.error("Aborting request because we have invalid authentication policy!");
                    containerRequestContext.abortWith(SERVER_ERROR);
            }
        } catch (IllegalStateException | AuthenticationException | InvalidSpecificationException cause) {
            containerRequestContext.abortWith(SERVER_ERROR);
        }
    }

    private void setAuthenticatorExecutorStack(Authentication authentication, AuthenticationConfiguration.Zone zone, ContainerRequestContext containerRequestContext) {
        JaxrsRequestAuthenticatorExecutor root = new RootRequestAuthenticatorExecutor(authenticationContextManager);
        JaxrsRequestAuthenticatorExecutor current = root;
        String authenticatorName = determineAuthenticatorName(authentication, zone);
        while (authenticatorName != null) {
            current.setOnFailure(AuthenticatorRegistry.lookup(authenticatorName, JaxrsRequestAuthenticator.class));
            current = current.getOnFailure();
            authenticatorName = configuration.getAuthenticators().get(authenticatorName).getOnFailure();
        }
        containerRequestContext.setProperty("authenticatorStack", root);
    }

    private void setHandshakeState(ContainerRequestContext containerRequestContext, Authentication authentication, AuthenticationConfiguration.Zone zone) throws InvalidSpecificationException {
        HandshakeState extractedState = extractHandshakeState(containerRequestContext);
        HandshakeState state = extractedState == null
                ? new HandshakeState(uriInfo.getRequestUri())
                : extractedState;
        containerRequestContext.setProperty("handshakeState", state);
    }

    private HandshakeState extractHandshakeState(ContainerRequestContext containerRequestContext) throws InvalidSpecificationException {
        String sessionId = configuration.getHandshake().getProtocol().getSessionId(containerRequestContext);
        String sessionData = configuration.getHandshake().getStore().retrieveSessionData(sessionId);
        return HandshakeState.fromString(sessionData);
    }

    private AuthenticationPolicy determinePolicy(Authentication authentication, AuthenticationConfiguration.Zone zone) {
        return authentication != null
                ? authentication.value()
                : zone != null ? zone.getPolicy() : AuthenticationPolicy.OPTIONAL;
    }

    private String determineAuthenticatorName(Authentication authentication, AuthenticationConfiguration.Zone zone) {
        return authentication != null && !authentication.authenticator().isEmpty()
                ? authentication.authenticator()
                : zone != null ? zone.getAuthenticator().getName() : "default";
    }

    private void handleNonePolicy(ContainerRequestContext containerRequestContext) {
        LOGGER.debug("Policy is NONE; skipping authentication");
    }

    private void handleOptionalPolicy(ContainerRequestContext containerRequestContext) throws AuthenticationException {
        Response response = authenticate(containerRequestContext);
        if (response != null) {
            containerRequestContext.abortWith(response);
        }
        LOGGER.debug("Policy is OPTIONAL, we are " + (!AuthenticationContext.isAuthenticated() ? "NOT " : "") + "authenticated");
    }

    private void handleRequiredPolicy(ContainerRequestContext containerRequestContext) throws AuthenticationException {
        Response response = authenticate(containerRequestContext);
        if (response != null) {
            containerRequestContext.abortWith(response);
        } else {
            if (AuthenticationContext.isAuthenticated()) {
                LOGGER.debug("Policy is REQUIRED, we are authenticated");
            } else {
                LOGGER.warn("Policy is REQUIRED, we are NOT authenticated; aborting request");
                containerRequestContext.abortWith(UNAUTHORIZED);
            }
        }
    }

    private Response authenticate(ContainerRequestContext containerRequestContext) throws AuthenticationException {
        HandshakeState state = (HandshakeState) containerRequestContext.getProperty("handshakeState");
        Map<String, JaxrsRequestAuthenticatorExecutor> map = (Map<String, JaxrsRequestAuthenticatorExecutor>) containerRequestContext.getProperty("excutorIndex");
        JaxrsRequestAuthenticatorExecutor root = map.get(state.getAuthenticatorNames().get(state.getAuthenticatorNames().size() - 1));
        return root.authenticate(containerRequestContext);
    }

}

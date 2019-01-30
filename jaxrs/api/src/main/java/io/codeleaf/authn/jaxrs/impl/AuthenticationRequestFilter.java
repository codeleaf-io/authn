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
import javax.ws.rs.core.Response;
import javax.ws.rs.core.SecurityContext;
import javax.ws.rs.core.UriInfo;
import java.net.URISyntaxException;
import java.security.Principal;
import java.util.Collections;
import java.util.List;

public final class AuthenticationRequestFilter implements ContainerRequestFilter {

    private static final Logger LOGGER = LoggerFactory.getLogger(AuthenticationRequestFilter.class);
    private static final Response UNAUTHORIZED = Response.status(Response.Status.UNAUTHORIZED).build();
    private static final Response SERVER_ERROR = Response.serverError().build();

    private final ThreadLocalAuthenticationContextManager authenticationContextManager;
    private final AuthenticationConfiguration configuration;

    @Context
    private ResourceInfo resourceInfo;

    @Context
    private UriInfo uriInfo;

    public AuthenticationRequestFilter(ThreadLocalAuthenticationContextManager authenticationContextManager, AuthenticationConfiguration configuration) {
        this.authenticationContextManager = authenticationContextManager;
        this.configuration = configuration;
    }

    @Override
    public void filter(ContainerRequestContext containerRequestContext) {
        LOGGER.debug("Processing authentication for endpoint: " + uriInfo.getPath());
        Authentication authentication = Authentications.getAuthentication(resourceInfo);
        if (authentication != null) {
            LOGGER.debug("We found an authentication annotation: " + authentication);
        }
        AuthenticationConfiguration.Zone zone = Zones.getZone(uriInfo.getPath(), configuration);
        if (zone != null) {
            LOGGER.debug(String.format("Zone matched: '%s' for: %s", zone.getName(), uriInfo.getPath()));
        }
        AuthenticationPolicy policy = determintePolicy(authentication, zone);
        String authenticatorName = determinteAuthenticatorName(authentication, zone);
        try {
            switch (policy) {
                case NONE:
                    handleNonePolicy(authenticatorName, containerRequestContext);
                    break;
                case OPTIONAL:
                    handleOptionalPolicy(authenticatorName, containerRequestContext);
                    break;
                case REQUIRED:
                    handleRequiredPolicy(authenticatorName, containerRequestContext);
                    break;
                default:
                    LOGGER.error("Aborting request because we have invalid authentication policy!");
                    containerRequestContext.abortWith(SERVER_ERROR);
            }
        } catch (IllegalStateException cause) {
            containerRequestContext.abortWith(SERVER_ERROR);
        }
    }

    private AuthenticationPolicy determintePolicy(Authentication authentication, AuthenticationConfiguration.Zone zone) {
        return authentication != null
                ? authentication.value()
                : zone != null ? zone.getPolicy() : AuthenticationPolicy.OPTIONAL;
    }

    private String determinteAuthenticatorName(Authentication authentication, AuthenticationConfiguration.Zone zone) {
        return authentication != null && !authentication.authenticator().isEmpty()
                ? authentication.authenticator()
                : zone != null ? zone.getAuthenticator().getName() : "default";
    }

    private void handleNonePolicy(String authenticatorName, ContainerRequestContext containerRequestContext) {
        LOGGER.debug("Policy is NONE; skipping authentication");
    }

    private void handleOptionalPolicy(String authenticatorName, ContainerRequestContext containerRequestContext) {
        if (!AuthenticatorRegistry.contains(authenticatorName, JaxrsRequestAuthenticator.class)) {
            LOGGER.warn("Policy is OPTIONAL, no JaxrsRequestAuthenticator implementation found with name: " + authenticatorName + "; skipping authentication");
            return;
        }
        LOGGER.debug(String.format("Authenticate using authenticator '%s'", authenticatorName));
        JaxrsRequestAuthenticator authenticator = AuthenticatorRegistry.lookup(authenticatorName, JaxrsRequestAuthenticator.class);
        authenticate(authenticator, containerRequestContext);
        LOGGER.debug("Policy is OPTIONAL, we are " + (!AuthenticationContext.isAuthenticated() ? "NOT " : "") + "authenticated");
    }


    private void handleRedirectPolicy(String authenticatorName, ContainerRequestContext containerRequestContext) throws URISyntaxException {
        if (!AuthenticatorRegistry.contains(authenticatorName, JaxrsRequestAuthenticator.class)) {
            LOGGER.warn("Policy is REDIRECT, no JaxrsRequestAuthenticator implementation found with name: " + authenticatorName + "; aborting request");
            containerRequestContext.abortWith(UNAUTHORIZED);
            return;
        }
        LOGGER.debug(String.format("Authenticate using authenticator '%s'", authenticatorName));
        JaxrsRequestAuthenticator authenticator = AuthenticatorRegistry.lookup(authenticatorName, JaxrsRequestAuthenticator.class);
        authenticate(authenticator, containerRequestContext);
        if (AuthenticationContext.isAuthenticated()) {
            LOGGER.debug("Policy is REQUIRED, we are authenticated");
        } else {
            LOGGER.warn("Policy is REQUIRED, we are NOT authenticated; aborting request with UNAUTHORIZED");
            containerRequestContext.abortWith(Response.status(Response.Status.UNAUTHORIZED).build());
        }
    }

    private void handleRequiredPolicy(String authenticatorName, ContainerRequestContext containerRequestContext) {
        if (!AuthenticatorRegistry.contains(authenticatorName, JaxrsRequestAuthenticator.class)) {
            LOGGER.warn("Policy is REQUIRED, no JaxrsRequestAuthenticator implementation found with name: " + authenticatorName + "; aborting request");
            containerRequestContext.abortWith(UNAUTHORIZED);
            return;
        }
        LOGGER.debug(String.format("Authenticate using authenticator '%s'", authenticatorName));
        JaxrsRequestAuthenticator authenticator = AuthenticatorRegistry.lookup(authenticatorName, JaxrsRequestAuthenticator.class);
        authenticate(Collections.singletonList(authenticator), containerRequestContext);
        if (AuthenticationContext.isAuthenticated()) {
            LOGGER.debug("Policy is REQUIRED, we are authenticated");
        } else {
            LOGGER.warn("Policy is REQUIRED, we are NOT authenticated; aborting request");
            containerRequestContext.abortWith(UNAUTHORIZED);
        }
    }

    private void authenticate(List<JaxrsRequestAuthenticator> authenticators, ContainerRequestContext containerRequestContext) {
        for (JaxrsRequestAuthenticator authenticator : authenticators) {
            authenticate(authenticator, containerRequestContext);
            if (containerRequestContext.getSecurityContext() != null
                    || authenticator.handleNotAuthenticated(containerRequestContext)) {
                break;
            }
        }
    }

    private void authenticate(JaxrsRequestAuthenticator authenticator, ContainerRequestContext containerRequestContext) {
        try {
            AuthenticationContext authenticationContext = authenticator.authenticate(containerRequestContext);
            if (authenticationContext != null) {
                authenticationContextManager.setAuthenticationContext(authenticationContext);
                containerRequestContext.setSecurityContext(createSecurityContext(authenticationContext, authenticator));
            }
        } catch (AuthenticationException cause) {
            LOGGER.debug("Failed to authenticate: " + cause.getMessage());
        }
    }

    private SecurityContext createSecurityContext(AuthenticationContext authenticationContext, JaxrsRequestAuthenticator authenticator) {
        return new SecurityContext() {
            @Override
            public Principal getUserPrincipal() {
                return authenticationContext.getPrincipal();
            }

            @Override
            public boolean isUserInRole(String role) {
                return false;
            }

            @Override
            public boolean isSecure() {
                return authenticationContext.isSecure();
            }

            @Override
            public String getAuthenticationScheme() {
                return authenticator.getAuthenticationScheme();
            }
        };
    }
}

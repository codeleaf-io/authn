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
import java.security.Principal;

/*
 /auth - does not do any authentication

 default JWT
 JWT.onFailure = Basic
 Basic.passwordAuthenticator = Dummy
 Dummy.userName = admin
 Dummy.password = 12345

 GET /abc = req1
 JWT.authenticate(req1) -> null (no header)
 JWT.handleNotAuthenticated(req1) -> false (no action taken, proceed)
 Basic.authenticate(req1) -> null (no header)
 Basic.handleNotAuthenticated(req1) -> true (Request.abortWith("/auth/Basic/login&authSessionId=XYZ"))

 GET /login&authSessionId=XYZ = req2
 JWT.onFailureCompleted(req2, authentication)

 GET

 GET /abc
 Authorization: Basic qwerqwerweqr

 /abc
 */
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
        LOGGER.debug(String.format("Authenticate using authenticator '%s'", authenticatorName));
        authenticate(authenticatorName, containerRequestContext);
        LOGGER.debug("Policy is OPTIONAL, we are " + (!AuthenticationContext.isAuthenticated() ? "NOT " : "") + "authenticated");
    }

    private void handleRequiredPolicy(String authenticatorName, ContainerRequestContext containerRequestContext) {
        LOGGER.debug(String.format("Authenticate using authenticator '%s'", authenticatorName));
        authenticate(authenticatorName, containerRequestContext);
        if (AuthenticationContext.isAuthenticated()) {
            LOGGER.debug("Policy is REQUIRED, we are authenticated");
        } else {
            LOGGER.warn("Policy is REQUIRED, we are NOT authenticated; aborting request");
            containerRequestContext.abortWith(UNAUTHORIZED);
//            if (!AuthenticationContext.isAuthenticated() && authenticator != null && authenticator.handleNotAuthenticated(containerRequestContext)) {
//                System.out.println("Redirecting to : " + authenticator.getLoginURI());
//                containerRequestContext.abortWith(Response.seeOther(authenticator.getLoginURI()).build());
//            }
        }
    }

//    private JaxrsRequestAuthenticator authenticate(List<JaxrsRequestAuthenticator> authenticators, ContainerRequestContext containerRequestContext) {
//        for (JaxrsRequestAuthenticator authenticator : authenticators) {
//            authenticate(authenticator, containerRequestContext);
//            if (AuthenticationContext.isAuthenticated()
//                    || authenticator.handleNotAuthenticated(containerRequestContext)) {
//                return authenticator;
//            }
//        }
//        return null;
//    }

    // TODO: verify and save state
    private AuthenticationContext authenticate(String authenticatorName, ContainerRequestContext containerRequestContext) {
        try {
            if (!AuthenticatorRegistry.contains(authenticatorName, JaxrsRequestAuthenticator.class)) {
                LOGGER.warn("No JaxrsRequestAuthenticator implementation found with name: " + authenticatorName);
                return null;
            }
            JaxrsRequestAuthenticator authenticator = AuthenticatorRegistry.lookup(authenticatorName, JaxrsRequestAuthenticator.class);
            AuthenticationContext authenticationContext = authenticator.authenticate(containerRequestContext);
            if (authenticationContext != null) {
                authenticationContextManager.setAuthenticationContext(authenticationContext);
                containerRequestContext.setSecurityContext(createSecurityContext(authenticationContext, authenticator));
            } else {
                Response.ResponseBuilder responseBuilder = authenticator.handleNotAuthenticated(containerRequestContext);
                if (responseBuilder != null) {
                    String onFailureAuthenticator = configuration.getAuthenticators().get(authenticatorName).getOnFailure();
                    if (onFailureAuthenticator != null && !onFailureAuthenticator.isEmpty()) {
                        authenticationContext = authenticate(onFailureAuthenticator, containerRequestContext);
                        authenticator.onFailureCompleted(containerRequestContext, authenticationContext);
                    }
                }
            }
            return authenticationContext;
        } catch (AuthenticationException cause) {
            LOGGER.debug("Failed to authenticate: " + cause.getMessage());
            return null;
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

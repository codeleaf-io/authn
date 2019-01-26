package io.codeleaf.authn.jaxrs.filters;

import io.codeleaf.authn.AuthenticationContext;
import io.codeleaf.authn.AuthenticationException;
import io.codeleaf.authn.impl.AuthenticatorRegistry;
import io.codeleaf.authn.impl.ThreadLocalAuthenticationContextManager;
import io.codeleaf.authn.jaxrs.Authentication;
import io.codeleaf.authn.jaxrs.AuthenticationPolicy;
import io.codeleaf.authn.jaxrs.config.JaxrsAuthenticationConfiguration;
import io.codeleaf.authn.jaxrs.spi.JaxrsRequestAuthenticator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.ws.rs.container.ContainerRequestContext;
import javax.ws.rs.container.ContainerRequestFilter;
import javax.ws.rs.container.ResourceInfo;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.UriInfo;
import java.lang.reflect.Method;
import java.util.Arrays;

public final class JaxrsAuthenticationRequestFilter implements ContainerRequestFilter {

    private static final Logger LOGGER = LoggerFactory.getLogger(JaxrsAuthenticationRequestFilter.class);
    private static final Response UNAUTHORIZED = Response.status(Response.Status.UNAUTHORIZED).build();
    private static final Response SERVER_ERROR = Response.serverError().build();

    private final ThreadLocalAuthenticationContextManager authenticationContextManager;
    private final JaxrsAuthenticationConfiguration configuration;

    @Context
    private ResourceInfo resourceInfo;

    @Context
    private UriInfo uriInfo;

    public JaxrsAuthenticationRequestFilter(ThreadLocalAuthenticationContextManager authenticationContextManager, JaxrsAuthenticationConfiguration configuration) {
        this.authenticationContextManager = authenticationContextManager;
        this.configuration = configuration;
    }

    @Override
    public void filter(ContainerRequestContext containerRequestContext) {
        LOGGER.debug("Processing authentication for endpoint: " + uriInfo.getPath());
        Authentication authentication = getAuthenticationAnnotation();
        if (authentication != null) {
            LOGGER.debug("We found an authentication annotation: " + authentication);
        }
        JaxrsAuthenticationConfiguration.Zone zone = getAuthenticationConfiguration();
        if (zone != null) {
            LOGGER.debug("We found a zone configuration: " + zone.getName());
        }
        AuthenticationPolicy policy = getPolicy(authentication, zone);
        String authenticatorName = getAuthenticatorName(authentication, zone);
        try {
            switch (policy) {
                case NONE:
                    LOGGER.debug("Policy is NONE, skipping authentication");
                    break;
                case OPTIONAL:
                    LOGGER.debug(String.format("Authenticate using Authenticator %s", authenticatorName));
                    authenticate(authenticatorName, containerRequestContext);
                    LOGGER.debug("Policy is OPTIONAL, we are " + (!AuthenticationContext.isAuthenticated() ? "NOT " : "") + "authenticated");
                    break;
                case REQUIRED:
                    LOGGER.debug(String.format("Authenticate using Authenticator %s", authenticatorName));
                    authenticate(authenticatorName, containerRequestContext);
                    LOGGER.debug("Policy is REQUIRED, we are " + (!AuthenticationContext.isAuthenticated() ? "NOT " : "") + "authenticated");
                    if (!AuthenticationContext.isAuthenticated()) {
                        LOGGER.warn("Aborting request because we are not authenticated!");
                        containerRequestContext.abortWith(UNAUTHORIZED);
                    }
                    break;
                default:
                    LOGGER.error("Aborting request because we have invalid authentication policy!");
                    containerRequestContext.abortWith(SERVER_ERROR);
            }
        } catch (IllegalStateException cause) {
            containerRequestContext.abortWith(SERVER_ERROR);
        }
    }

    private AuthenticationPolicy getPolicy(Authentication authentication, JaxrsAuthenticationConfiguration.Zone zone) {
        return authentication != null
                ? authentication.value()
                : zone != null ? zone.getPolicy() : AuthenticationPolicy.OPTIONAL;
    }

    private String getAuthenticatorName(Authentication authentication, JaxrsAuthenticationConfiguration.Zone zone) {
        return authentication != null && !authentication.authenticator().isEmpty()
                ? authentication.authenticator()
                : zone != null ? zone.getAuthenticator().getName() : "default";
    }

    private void authenticate(String authenticatorName, ContainerRequestContext containerRequestContext) {
        try {
            JaxrsRequestAuthenticator authenticator = AuthenticatorRegistry.lookup(authenticatorName, JaxrsRequestAuthenticator.class);
            if (authenticator == null) {
                LOGGER.error("No authenticator registered with name: " + authenticatorName);
                throw new IllegalStateException("No authenticator registered with name: " + authenticatorName);
            }
            authenticationContextManager.setAuthenticationContext(authenticator.authenticate(containerRequestContext));
        } catch (AuthenticationException cause) {
            LOGGER.debug("Failed to authenticate: " + cause.getMessage());
        }
    }

    private Authentication getAuthenticationAnnotation() {
        Authentication authentication;
        Authentication methodAuthentication = getMethodAuthentication();
        if (methodAuthentication != null) {
            authentication = methodAuthentication;
        } else {
            Authentication classAuthentication = getClassAuthentication();
            if (classAuthentication != null) {
                authentication = classAuthentication;
            } else {
                authentication = null;
            }
        }
        return authentication;
    }

    private Authentication getMethodAuthentication() {
        Method method = resourceInfo.getResourceMethod();
        Authentication authentication;
        Authentication declaredAuthentication = method.getAnnotation(Authentication.class);
        if (declaredAuthentication != null) {
            authentication = declaredAuthentication;
        } else {
            Authentication inheritedMethodPolicy = getInheritedMethodAuthentication();
            if (inheritedMethodPolicy != null) {
                authentication = inheritedMethodPolicy;
            } else {
                authentication = null;
            }
        }
        return authentication;
    }

    private Authentication getInheritedMethodAuthentication() {
        Method method = resourceInfo.getResourceMethod();
        for (Class<?> clazz = method.getDeclaringClass().getSuperclass(); !clazz.equals(Object.class); clazz = clazz.getSuperclass()) {
            for (Method declaredMethod : clazz.getDeclaredMethods()) {
                if (declaredMethod.getName().equals(method.getName()) && Arrays.equals(declaredMethod.getParameterTypes(), method.getParameterTypes())) {
                    Authentication authentication = declaredMethod.getAnnotation(Authentication.class);
                    if (authentication != null) {
                        return authentication;
                    }
                }
            }
        }
        return null;
    }

    private Authentication getClassAuthentication() {
        Class<?> clazz = resourceInfo.getResourceClass();
        Authentication authentication;
        Authentication declaredAuthentication = clazz.getAnnotation(Authentication.class);
        if (declaredAuthentication != null) {
            authentication = declaredAuthentication;
        } else {
            Authentication inheritedClassAuthentication = getInheritedClassAuthentication();
            if (inheritedClassAuthentication != null) {
                authentication = inheritedClassAuthentication;
            } else {
                authentication = null;
            }
        }
        return authentication;
    }

    private Authentication getInheritedClassAuthentication() {
        for (Class<?> clazz = resourceInfo.getResourceClass(); !clazz.equals(Object.class); clazz = clazz.getSuperclass()) {
            Authentication authentication = clazz.getAnnotation(Authentication.class);
            if (authentication != null) {
                return authentication;
            }
        }
        return null;
    }

    private JaxrsAuthenticationConfiguration.Zone getAuthenticationConfiguration() {
        for (JaxrsAuthenticationConfiguration.Zone zone : configuration.getZones()) {
            for (String endpoint : zone.getEndpoints()) {
                if (endpointMatches(endpoint, uriInfo)) {
                    return zone;
                }
            }
        }
        return null;
    }

    // TODO: support better patterns
    private boolean endpointMatches(String endpoint, UriInfo uriInfo) {
        boolean matches = endpoint.endsWith("*") ? uriInfo.getPath().startsWith(endpoint.substring(0, endpoint.length() - 1)) : endpoint.equals(uriInfo.getPath());
        LOGGER.debug(String.format("Matches %s to %s? %s", endpoint, uriInfo.getPath(), matches));
        return matches;
    }
}

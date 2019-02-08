package io.codeleaf.authn.jaxrs.impl;

import io.codeleaf.authn.AuthenticationContext;
import io.codeleaf.authn.AuthenticationException;
import io.codeleaf.authn.impl.ThreadLocalAuthenticationContextManager;
import io.codeleaf.authn.jaxrs.spi.JaxrsRequestAuthenticator;

import javax.ws.rs.container.ContainerRequestContext;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.SecurityContext;
import java.security.Principal;

public final class RootRequestAuthenticatorExecutor extends JaxrsRequestAuthenticatorExecutor {

    private final ThreadLocalAuthenticationContextManager authenticationContextManager;

    public RootRequestAuthenticatorExecutor(ThreadLocalAuthenticationContextManager authenticationContextManager) {
        super(null, null);
        this.authenticationContextManager = authenticationContextManager;
    }

    public Response authenticate(ContainerRequestContext requestContext) throws AuthenticationException {
        return getOnFailure().authenticate(requestContext);
    }

    public Response onFailureCompleted(ContainerRequestContext requestContext, AuthenticationContext authenticationContext) {
        authenticationContextManager.setAuthenticationContext(authenticationContext);
        requestContext.setSecurityContext(createSecurityContext(authenticationContext, getOnFailure().getAuthenticator()));
        return null;
    }

    @Override
    public JaxrsRequestAuthenticator getParent() {
        return null;
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
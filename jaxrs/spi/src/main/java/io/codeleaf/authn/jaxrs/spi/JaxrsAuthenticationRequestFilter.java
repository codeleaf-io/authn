package io.codeleaf.authn.jaxrs.spi;

import io.codeleaf.authn.AuthenticationException;
import io.codeleaf.authn.impl.ThreadLocalAuthenticationContextManager;

import javax.ws.rs.container.ContainerRequestContext;
import javax.ws.rs.container.ContainerRequestFilter;
import java.io.IOException;

public final class JaxrsAuthenticationRequestFilter implements ContainerRequestFilter {

    private final JaxrsRequestAuthenticator jaxrsRequestAuthenticator;
    private final ThreadLocalAuthenticationContextManager authenticationContextManager;

    public JaxrsAuthenticationRequestFilter(JaxrsRequestAuthenticator jaxrsRequestAuthenticator, ThreadLocalAuthenticationContextManager authenticationContextManager) {
        this.jaxrsRequestAuthenticator = jaxrsRequestAuthenticator;
        this.authenticationContextManager = authenticationContextManager;
    }

    @Override
    public void filter(ContainerRequestContext containerRequestContext) throws IOException {
        try {
            authenticationContextManager.setAuthenticationContext(jaxrsRequestAuthenticator.authenticate(containerRequestContext));
        } catch (AuthenticationException ignored) {
        }
    }
}

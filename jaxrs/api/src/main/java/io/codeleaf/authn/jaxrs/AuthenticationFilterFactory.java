package io.codeleaf.authn.jaxrs;

import io.codeleaf.authn.AuthenticationContext;
import io.codeleaf.authn.impl.ThreadLocalAuthenticationContextManager;
import io.codeleaf.authn.jaxrs.impl.ZoneHandlerPreServiceFilter;
import io.codeleaf.authn.jaxrs.impl.ZoneHandlerPostServiceFilter;
import io.codeleaf.config.ConfigurationException;
import io.codeleaf.config.ConfigurationProvider;

import javax.ws.rs.container.ContainerRequestFilter;
import javax.ws.rs.container.ContainerResponseFilter;
import java.io.IOException;

public final class AuthenticationFilterFactory {

    private final ThreadLocalAuthenticationContextManager authenticationContextManager;
    private final AuthenticationConfiguration configuration;

    public AuthenticationFilterFactory(ThreadLocalAuthenticationContextManager authenticationContextManager,
                                       AuthenticationConfiguration configuration) {
        this.authenticationContextManager = authenticationContextManager;
        this.configuration = configuration;
    }

    public ContainerRequestFilter createRequestFilter() {
        return new ZoneHandlerPreServiceFilter(authenticationContextManager, configuration);
    }

    public ContainerResponseFilter createResponseFilter() {
        return new ZoneHandlerPostServiceFilter(authenticationContextManager);
    }

    public static AuthenticationFilterFactory create() throws ConfigurationException, IOException {
        return new AuthenticationFilterFactory(
                (ThreadLocalAuthenticationContextManager) AuthenticationContext.Holder.get(),
                ConfigurationProvider.get().getConfiguration(AuthenticationConfiguration.class));
    }
}

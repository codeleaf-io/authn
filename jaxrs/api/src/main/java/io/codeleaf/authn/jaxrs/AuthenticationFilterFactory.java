package io.codeleaf.authn.jaxrs;

import io.codeleaf.authn.AuthenticationContext;
import io.codeleaf.authn.impl.ThreadLocalAuthenticationContextManager;
import io.codeleaf.authn.jaxrs.impl.HandshakeStateHandler;
import io.codeleaf.authn.jaxrs.impl.ZoneHandlerPostServiceFilter;
import io.codeleaf.authn.jaxrs.impl.ZoneHandlerPreServiceFilter;
import io.codeleaf.config.ConfigurationException;
import io.codeleaf.config.ConfigurationProvider;

import javax.ws.rs.container.ContainerRequestFilter;
import javax.ws.rs.container.ContainerResponseFilter;
import java.io.IOException;

public final class AuthenticationFilterFactory {

    private final ThreadLocalAuthenticationContextManager authenticationContextManager;
    private final AuthenticationConfiguration configuration;
    private final HandshakeStateHandler handshakeStateHandler;

    public AuthenticationFilterFactory(ThreadLocalAuthenticationContextManager authenticationContextManager,
                                       AuthenticationConfiguration configuration, HandshakeStateHandler handshakeStateHandler) {
        this.authenticationContextManager = authenticationContextManager;
        this.configuration = configuration;
        this.handshakeStateHandler = handshakeStateHandler;
    }

    public ContainerRequestFilter createRequestFilter() {
        return new ZoneHandlerPreServiceFilter(authenticationContextManager, configuration, handshakeStateHandler);
    }

    public ContainerResponseFilter createResponseFilter() {
        return new ZoneHandlerPostServiceFilter(handshakeStateHandler);
    }

    public static AuthenticationFilterFactory create() throws ConfigurationException, IOException {
        AuthenticationConfiguration configuration = ConfigurationProvider.get().getConfiguration(AuthenticationConfiguration.class);
        return new AuthenticationFilterFactory(
                (ThreadLocalAuthenticationContextManager) AuthenticationContext.Holder.get(),
                configuration,
                new HandshakeStateHandler(configuration.getHandshake()));
    }
}

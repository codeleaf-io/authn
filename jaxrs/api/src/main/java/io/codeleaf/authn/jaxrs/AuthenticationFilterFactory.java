package io.codeleaf.authn.jaxrs;

import io.codeleaf.authn.AuthenticationContext;
import io.codeleaf.authn.impl.ThreadLocalAuthenticationContextManager;
import io.codeleaf.authn.jaxrs.impl.HandshakeStateHandler;
import io.codeleaf.authn.jaxrs.impl.ZoneHandler;
import io.codeleaf.config.ConfigurationException;
import io.codeleaf.config.ConfigurationProvider;

import java.io.IOException;
import java.util.Set;

public final class AuthenticationFilterFactory {

    private AuthenticationFilterFactory() {
    }

    public static Set<Object> create() {
        try {
            AuthenticationConfiguration configuration = ConfigurationProvider.get().getConfiguration(AuthenticationConfiguration.class);
            return new ZoneHandler(
                    (ThreadLocalAuthenticationContextManager) AuthenticationContext.Holder.get(),
                    configuration,
                    new HandshakeStateHandler(configuration.getHandshake())).getFilters();
        } catch (ConfigurationException | IOException cause) {
            throw new ExceptionInInitializerError(cause);
        }
    }
}

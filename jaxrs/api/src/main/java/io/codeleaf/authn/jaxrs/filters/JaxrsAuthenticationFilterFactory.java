package io.codeleaf.authn.jaxrs.filters;

import io.codeleaf.authn.AuthenticationContext;
import io.codeleaf.authn.impl.ThreadLocalAuthenticationContextManager;
import io.codeleaf.authn.jaxrs.config.JaxrsAuthenticationConfiguration;
import io.codeleaf.authn.jaxrs.spi.JaxrsRequestAuthenticator;
import io.codeleaf.common.utils.SingletonServiceLoader;
import io.codeleaf.config.ConfigurationException;
import io.codeleaf.config.ConfigurationProvider;

import java.io.IOException;

public final class JaxrsAuthenticationFilterFactory {

    private final ThreadLocalAuthenticationContextManager authenticationContextManager;
    private final JaxrsAuthenticationConfiguration configuration;

    public JaxrsAuthenticationFilterFactory(ThreadLocalAuthenticationContextManager authenticationContextManager,
                                            JaxrsAuthenticationConfiguration configuration) {
        this.authenticationContextManager = authenticationContextManager;
        this.configuration = configuration;
    }

    public JaxrsAuthenticationRequestFilter createRequestFilter() {
        return new JaxrsAuthenticationRequestFilter(authenticationContextManager, configuration);
    }

    public JaxrsAuthenticationResponseFilter createResponseFilter() {
        return new JaxrsAuthenticationResponseFilter(authenticationContextManager);
    }

    public static JaxrsAuthenticationFilterFactory create() throws ConfigurationException, IOException {
        return new JaxrsAuthenticationFilterFactory(
                (ThreadLocalAuthenticationContextManager) AuthenticationContext.Holder.get(),
                ConfigurationProvider.get().getConfiguration(JaxrsAuthenticationConfiguration.class));
    }
}

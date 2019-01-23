package io.codeleaf.authn.jaxrs.spi;

import io.codeleaf.authn.AuthenticationContext;
import io.codeleaf.authn.impl.ThreadLocalAuthenticationContextManager;
import io.codeleaf.common.utils.SingletonServiceLoader;

public final class JaxrsAuthenticationFilterFactory {

    private final ThreadLocalAuthenticationContextManager authenticationContextManager;
    private final JaxrsRequestAuthenticator jaxrsRequestAuthenticator;

    public JaxrsAuthenticationFilterFactory(ThreadLocalAuthenticationContextManager authenticationContextManager,
                                            JaxrsRequestAuthenticator jaxrsRequestAuthenticator) {
        this.authenticationContextManager = authenticationContextManager;
        this.jaxrsRequestAuthenticator = jaxrsRequestAuthenticator;
    }

    public JaxrsAuthenticationRequestFilter createRequestFilter() {
        return new JaxrsAuthenticationRequestFilter(jaxrsRequestAuthenticator, authenticationContextManager);
    }

    public JaxrsAuthenticationResponseFilter createResponseFilter() {
        return new JaxrsAuthenticationResponseFilter(authenticationContextManager);
    }

    public static JaxrsAuthenticationFilterFactory create() {
        return new JaxrsAuthenticationFilterFactory((ThreadLocalAuthenticationContextManager) AuthenticationContext.Holder.get(),
                SingletonServiceLoader.load(JaxrsRequestAuthenticator.class));
    }
}

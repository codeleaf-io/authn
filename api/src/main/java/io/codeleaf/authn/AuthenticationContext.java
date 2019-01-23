package io.codeleaf.authn;

import io.codeleaf.authn.spi.AuthenticationContextProvider;
import io.codeleaf.common.utils.SingletonServiceLoader;

import java.security.Principal;
import java.util.Map;

public interface AuthenticationContext {

    Principal getPrincipal();

    default String getIdentity() {
        return getPrincipal().getName();
    }

    Map<String, Object> getAttributes();

    boolean isSecure();

    static boolean isAuthenticated() {
        return Holder.get().isAuthenticated();
    }

    static AuthenticationContext get() throws NotAuthenticatedException {
        if (!isAuthenticated()) throw new NotAuthenticatedException();
        return Holder.get().getAuthenticationContext();
    }

    /**
     * Holder for a authentication context provider, to obtain the authentication context, use {@link #get()}
     */
    final class Holder {

        private Holder() {
        }

        private static AuthenticationContextProvider INSTANCE;

        static {
            init();
        }

        private static void init() {
            try {
                INSTANCE = SingletonServiceLoader.load(AuthenticationContextProvider.class);
            } catch (Exception cause) {
                throw new ExceptionInInitializerError(cause);
            }
        }

        public static AuthenticationContextProvider get() {
            return INSTANCE;
        }

    }
}
package io.codeleaf.authn;

import io.codeleaf.authn.impl.ThreadLocalAuthenticationContextProvider;

import java.security.Principal;
import java.util.Map;

public interface AuthenticationContext {

    /**
     * Holder for a authentication context provider, to obtain the authentication context, use {@link #get()}
     */
    final class Holder {

        private static ThreadLocalAuthenticationContextProvider INSTANCE;

        static {
            init();
        }

        private static void init() {
            try {
                INSTANCE = new ThreadLocalAuthenticationContextProvider();
            } catch (Exception cause) {
                throw new ExceptionInInitializerError(cause);
            }
        }

        private static ThreadLocalAuthenticationContextProvider get() {
            return INSTANCE;
        }

        private Holder() {
        }

    }

    static boolean isAuthenticated(){
        return Holder.get().isAuthenticated();
    }

    static AuthenticationContext get() throws NotAuthenticatedException{
        if(!isAuthenticated()) throw new NotAuthenticatedException();
        return Holder.get().getAuthenticationContext();
    }

    Principal getPrincipal();

    default String getIdentity(){
       return getPrincipal().getName();
    }

    Map<String, Object> getAttributes();

    boolean isSecure();
}
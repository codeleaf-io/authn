package io.codeleaf.authn.jaxrs;

import io.codeleaf.authn.jaxrs.impl.AuthenticatorResources;
import io.codeleaf.authn.jaxrs.impl.SecureApplicationCorsFilter;

import javax.ws.rs.core.Application;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.Set;

public class SecureApplication extends Application {

    private final AuthenticationFilterFactory factory;

    public SecureApplication() {
        try {
            this.factory = AuthenticationFilterFactory.create();
        } catch (Exception cause) {
            throw new ExceptionInInitializerError(cause);
        }
    }

    protected Set<Class<?>> getSecureClasses() {
        return Collections.emptySet();
    }

    protected Set<Object> getSecureSingletons() {
        return Collections.emptySet();
    }

    public final Set<Class<?>> getClasses() {
        return getSecureClasses();
    }

    public final Set<Object> getSingletons() {
        Set<Object> singletons = new LinkedHashSet<>();
        singletons.addAll(AuthenticatorResources.create().getAllResources());
        singletons.add(factory.createRequestFilter());
        singletons.addAll(getSecureSingletons());
        singletons.add(factory.createResponseFilter());
        singletons.add(new SecureApplicationCorsFilter());
        return singletons;
    }
}

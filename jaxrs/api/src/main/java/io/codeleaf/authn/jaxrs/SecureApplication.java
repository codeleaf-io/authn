package io.codeleaf.authn.jaxrs;

import io.codeleaf.authn.jaxrs.impl.AuthenticatorResources;
import io.codeleaf.config.ConfigurationException;

import javax.ws.rs.core.Application;
import java.io.IOException;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.Set;

public class SecureApplication extends Application {

    protected Set<Class<?>> getSecureClasses() {
        return Collections.emptySet();
    }

    protected Set<Object> getSecureSingletons() {
        return Collections.emptySet();
    }

    public final Set<Class<?>> getClasses() {
        Set<Class<?>> classes = new LinkedHashSet<>();
        classes.add(AuthenticatorResources.class);
        classes.addAll(getSecureClasses());
        return classes;
    }

    public final Set<Object> getSingletons() {
        try {
            Set<Object> singletons = new LinkedHashSet<>(AuthenticationFilterFactory.create());
            singletons.addAll(getSecureSingletons());
            return singletons;
        } catch (ConfigurationException | IOException cause) {
            throw new ExceptionInInitializerError(cause);
        }
    }
}

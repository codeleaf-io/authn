package io.codeleaf.authn.jaxrs;

import io.codeleaf.authn.jaxrs.impl.AuthenticatorResources;
import io.codeleaf.config.ConfigurationException;
import io.codeleaf.config.ConfigurationProvider;

import javax.ws.rs.core.Application;
import java.io.IOException;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.Set;

public class SecureApplication extends Application {

    private final AuthenticationConfiguration config;

    public SecureApplication() throws ConfigurationException, IOException {
        this(ConfigurationProvider.get().getConfiguration(AuthenticationConfiguration.class));
    }

    public SecureApplication(AuthenticationConfiguration config) {
        this.config = config;
    }

    protected Set<Class<?>> getSecureClasses() {
        return Collections.emptySet();
    }

    protected Set<Object> getSecureSingletons() {
        return Collections.emptySet();
    }

    public final Set<Class<?>> getClasses() {
        Set<Class<?>> classes = new LinkedHashSet<>();
        classes.addAll(getSecureClasses());
        return classes;
    }

    public final Set<Object> getSingletons() {
        Set<Object> singletons = new LinkedHashSet<>(AuthenticationFilterFactory.create(config));
        singletons.add(AuthenticatorResources.create(config));
        singletons.addAll(getSecureSingletons());
        return singletons;
    }

}

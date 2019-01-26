package io.codeleaf.authn.jaxrs.config;

import io.codeleaf.authn.jaxrs.AuthenticationPolicy;
import io.codeleaf.config.Configuration;

import java.util.*;

public final class JaxrsAuthenticationConfiguration implements Configuration {

    private final List<Zone> zones;
    private final Map<String, Authenticator> authenticators;

    private JaxrsAuthenticationConfiguration(List<Zone> zones, Map<String, Authenticator> authenticators) {
        this.zones = zones;
        this.authenticators = authenticators;
    }

    public List<Zone> getZones() {
        return zones;
    }

    public Map<String, Authenticator> getAuthenticators() {
        return authenticators;
    }

    public static JaxrsAuthenticationConfiguration create(List<Zone> zones, Map<String, Authenticator> authenticators) {
        Objects.requireNonNull(zones);
        Objects.requireNonNull(authenticators);
        return new JaxrsAuthenticationConfiguration(
                Collections.unmodifiableList(new ArrayList<>(zones)),
                Collections.unmodifiableMap(new LinkedHashMap<>(authenticators)));
    }

    private static final JaxrsAuthenticationConfiguration DEFAULT = create(Collections.emptyList(), Collections.emptyMap());

    public static final JaxrsAuthenticationConfiguration getDefault() {
        return DEFAULT;
    }

    public static class Zone {

        private final String name;
        private final AuthenticationPolicy policy;
        private final List<String> endpoints;
        private final Authenticator authenticator;

        Zone(String name, AuthenticationPolicy policy, List<String> endpoints, Authenticator authenticator) {
            this.name = name;
            this.policy = policy;
            this.endpoints = endpoints;
            this.authenticator = authenticator;
        }

        public String getName() {
            return name;
        }

        public AuthenticationPolicy getPolicy() {
            return policy;
        }

        public List<String> getEndpoints() {
            return endpoints;
        }

        public Authenticator getAuthenticator() {
            return authenticator;
        }
    }

    public static class Authenticator {

        private final String name;
        private final Class<?> implementationClass;
        private final Configuration configuration;

        Authenticator(String name, Class<?> implementationClass, Configuration configuration) {
            this.name = name;
            this.implementationClass = implementationClass;
            this.configuration = configuration;
        }

        public String getName() {
            return name;
        }

        public Class<?> getImplementationClass() {
            return implementationClass;
        }

        public Configuration getConfiguration() {
            return configuration;
        }
    }
}

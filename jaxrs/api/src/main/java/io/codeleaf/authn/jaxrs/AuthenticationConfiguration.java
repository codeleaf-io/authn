package io.codeleaf.authn.jaxrs;

import io.codeleaf.config.Configuration;

import java.util.*;

public final class AuthenticationConfiguration implements Configuration {

    private final List<Zone> zones;
    private final Map<String, Authenticator> authenticators;

    private AuthenticationConfiguration(List<Zone> zones, Map<String, Authenticator> authenticators) {
        this.zones = zones;
        this.authenticators = authenticators;
    }

    public List<Zone> getZones() {
        return zones;
    }

    public Map<String, Authenticator> getAuthenticators() {
        return authenticators;
    }

    public static AuthenticationConfiguration create(List<Zone> zones, Map<String, Authenticator> authenticators) {
        Objects.requireNonNull(zones);
        Objects.requireNonNull(authenticators);
        return new AuthenticationConfiguration(
                Collections.unmodifiableList(new ArrayList<>(zones)),
                Collections.unmodifiableMap(new LinkedHashMap<>(authenticators)));
    }

    private static final AuthenticationConfiguration DEFAULT = create(Collections.emptyList(), Collections.emptyMap());

    public static final AuthenticationConfiguration getDefault() {
        return DEFAULT;
    }

    public static final class Zone {

        private final String name;
        private final AuthenticationPolicy policy;
        private final List<String> endpoints;
        private final Authenticator authenticator;

        public Zone(String name, AuthenticationPolicy policy, List<String> endpoints, Authenticator authenticator) {
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

    public static final class Authenticator {

        private final String name;
        private final Class<?> implementationClass;
        private final String onFailure;
        private final Configuration configuration;

        public Authenticator(String name, Class<?> implementationClass, String onFailure, Configuration configuration) {
            this.name = name;
            this.implementationClass = implementationClass;
            this.onFailure = onFailure;
            this.configuration = configuration;
        }

        public String getName() {
            return name;
        }

        public Class<?> getImplementationClass() {
            return implementationClass;
        }

        public String getOnFailure() {
            return onFailure;
        }

        public Configuration getConfiguration() {
            return configuration;
        }
    }
}

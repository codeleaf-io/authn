package io.codeleaf.authn.jaxrs.impl;

import io.codeleaf.authn.jaxrs.AuthenticationConfiguration;

public final class Zones {

    private Zones() {
    }

    public static AuthenticationConfiguration.Zone getZone(String requestPath, AuthenticationConfiguration configuration) {
        for (AuthenticationConfiguration.Zone zone : configuration.getZones()) {
            for (String endpoint : zone.getEndpoints()) {
                if (endpointMatches(endpoint, requestPath)) {
                    return zone;
                }
            }
        }
        return null;
    }

    private static boolean endpointMatches(String endpoint, String requestPath) {
        return requestPath.matches(endpoint);
    }
}

package io.codeleaf.authn.jaxrs.impl;

import io.codeleaf.authn.impl.AuthenticatorRegistry;
import io.codeleaf.authn.jaxrs.spi.JaxrsRequestAuthenticator;

import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import java.util.LinkedHashMap;
import java.util.Map;

@Path("authn")
public final class AuthenticatorResources {

    private final Map<String, Object> resources;

    public AuthenticatorResources() {
        this(getResources());
    }

    public AuthenticatorResources(Map<String, Object> resources) {
        this.resources = resources;
    }

    @Path("{authenticatorName}")
    public Object handleRequest(@PathParam("authenticatorName") String authenticatorName) {
        return resources.get(authenticatorName);
    }

    private static Map<String, Object> getResources() {
        Map<String, Object> resources = new LinkedHashMap<>();
        for (String name : AuthenticatorRegistry.getNames(JaxrsRequestAuthenticator.class)) {
            JaxrsRequestAuthenticator authenticator = AuthenticatorRegistry.lookup(name, JaxrsRequestAuthenticator.class);
            Object resource = authenticator.getResource();
            if (resource != null) {
                resources.put(name, resource);
            }
        }
        return resources;
    }
}

package io.codeleaf.authn.jaxrs.impl;

import io.codeleaf.authn.impl.AuthenticatorRegistry;
import io.codeleaf.authn.jaxrs.spi.JaxrsRequestAuthenticator;

import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import java.util.LinkedHashMap;
import java.util.Map;

@Path("auth")
public final class AuthenticatorResources {

    private final Map<String, Object> resources;

    public AuthenticatorResources(Map<String, Object> resources) {
        this.resources = resources;
    }

    @Path("{name}/*")
    public Object getResource(@PathParam("name") String name) {
        return resources.get(name);
    }

    public static AuthenticatorResources create() {
        Map<String, Object> resources = new LinkedHashMap<>();
        for (String name : AuthenticatorRegistry.getNames(JaxrsRequestAuthenticator.class)) {
            JaxrsRequestAuthenticator authenticator = AuthenticatorRegistry.lookup(name, JaxrsRequestAuthenticator.class);
            Object resource = authenticator.getResource();
            if (resource != null) {
                resources.put(name, resource);
            }
        }
        return new AuthenticatorResources(resources);
    }
}

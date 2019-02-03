package io.codeleaf.authn.jaxrs.impl;

import org.jboss.resteasy.plugins.interceptors.CorsFilter;

public class SecureApplicationCorsFilter extends CorsFilter {

    public SecureApplicationCorsFilter() {
        getAllowedOrigins().add("*");
        setAllowCredentials(true);
        setAllowedMethods("OPTIONS, GET, POST, DELETE, PUT, PATCH");
    }
}

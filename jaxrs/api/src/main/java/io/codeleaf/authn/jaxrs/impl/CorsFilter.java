package io.codeleaf.authn.jaxrs.impl;

import javax.ws.rs.ForbiddenException;
import javax.ws.rs.container.*;
import javax.ws.rs.core.Response;
import java.io.IOException;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

@PreMatching
public final class CorsFilter implements ContainerRequestFilter, ContainerResponseFilter {

    private boolean allowCredentials = true;
    private String allowedMethods;
    private String allowedHeaders;
    private String exposedHeaders;
    private int corsMaxAge = -1;
    private Set<String> allowedOrigins = new HashSet<>();

    public Set<String> getAllowedOrigins() {
        return this.allowedOrigins;
    }

    public boolean isAllowCredentials() {
        return this.allowCredentials;
    }

    public void setAllowCredentials(boolean allowCredentials) {
        this.allowCredentials = allowCredentials;
    }

    public String getAllowedMethods() {
        return this.allowedMethods;
    }

    public void setAllowedMethods(String allowedMethods) {
        this.allowedMethods = allowedMethods;
    }

    public String getAllowedHeaders() {
        return this.allowedHeaders;
    }

    public void setAllowedHeaders(String allowedHeaders) {
        this.allowedHeaders = allowedHeaders;
    }

    public int getCorsMaxAge() {
        return this.corsMaxAge;
    }

    public void setCorsMaxAge(int corsMaxAge) {
        this.corsMaxAge = corsMaxAge;
    }

    public String getExposedHeaders() {
        return this.exposedHeaders;
    }

    public void setExposedHeaders(String exposedHeaders) {
        this.exposedHeaders = exposedHeaders;
    }

    public void filter(ContainerRequestContext requestContext) throws IOException {
        String origin = requestContext.getHeaderString("Origin");
        if (origin != null) {
            if (requestContext.getMethod().equalsIgnoreCase("OPTIONS")) {
                preflight(origin, requestContext);
            } else {
                checkOrigin(requestContext, origin);
            }
        }
    }

    public void filter(ContainerRequestContext requestContext, ContainerResponseContext responseContext) throws IOException {
        String origin = requestContext.getHeaderString("Origin");
        if (origin != null && !requestContext.getMethod().equalsIgnoreCase("OPTIONS") && requestContext.getProperty("cors.failure") == null) {
            responseContext.getHeaders().putSingle("Access-Control-Allow-Origin", origin);
            responseContext.getHeaders().putSingle("Vary", "Origin");
            if (allowCredentials) {
                responseContext.getHeaders().putSingle("Access-Control-Allow-Credentials", "true");
            }
            if (exposedHeaders != null) {
                responseContext.getHeaders().putSingle("Access-Control-Expose-Headers", this.exposedHeaders);
            }
        }
    }

    private void preflight(String origin, ContainerRequestContext requestContext) throws IOException {
        checkOrigin(requestContext, origin);
        Response.ResponseBuilder builder = Response.ok();
        builder.header("Access-Control-Allow-Origin", origin);
        builder.header("Vary", "Origin");
        if (this.allowCredentials) {
            builder.header("Access-Control-Allow-Credentials", "true");
        }
        String requestMethods = requestContext.getHeaderString("Access-Control-Request-Method");
        if (requestMethods != null) {
            if (this.allowedMethods != null) {
                requestMethods = this.allowedMethods;
            }
            builder.header("Access-Control-Allow-Methods", requestMethods);
        }
        String allowHeaders = requestContext.getHeaderString("Access-Control-Request-Headers");
        if (allowHeaders != null) {
            if (this.allowedHeaders != null) {
                allowHeaders = this.allowedHeaders;
            }
            builder.header("Access-Control-Allow-Headers", allowHeaders);
        }
        if (this.corsMaxAge > -1) {
            builder.header("Access-Control-Max-Age", this.corsMaxAge);
        }
        requestContext.abortWith(builder.build());
    }

    private void checkOrigin(ContainerRequestContext requestContext, String origin) {
        if (!this.allowedOrigins.contains("*") && !this.allowedOrigins.contains(origin)) {
            requestContext.setProperty("cors.failure", true);
            throw new ForbiddenException("Origin not allowed: " + origin);
        }
    }

    public static CorsFilter create() {
        return create(Collections.singletonList("*"));
    }

    public static CorsFilter create(List<String> allowedOrigins) {
        CorsFilter corsFilter = new CorsFilter();
        corsFilter.getAllowedOrigins().addAll(allowedOrigins);
        corsFilter.setAllowCredentials(true);
        corsFilter.setAllowedMethods("OPTIONS, GET, POST, DELETE, PUT, PATCH");
        return corsFilter;
    }

}

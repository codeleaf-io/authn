package io.codeleaf.authn.jaxrs;

public enum AuthenticationPolicy {
    REQUIRED, // must be authenticated or won't proceed
    OPTIONAL, // authentication is optional
    NONE // no authentication will happen, even if credentials were provided
}

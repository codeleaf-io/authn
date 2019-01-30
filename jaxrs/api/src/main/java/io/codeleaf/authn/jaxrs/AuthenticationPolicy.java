package io.codeleaf.authn.jaxrs;

public enum AuthenticationPolicy {
    REQUIRED, // must be authenticated or won't proceed
    REDIRECT, // must be authenticated if not redirect to loginURL for authentication
    OPTIONAL, // authentication is optional
    NONE // no authentication will happen, even if credentials were provided
}

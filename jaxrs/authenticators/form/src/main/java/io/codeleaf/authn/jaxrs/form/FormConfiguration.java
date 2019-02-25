package io.codeleaf.authn.jaxrs.form;

import io.codeleaf.authn.password.spi.PasswordRequestAuthenticator;
import io.codeleaf.config.Configuration;

import java.net.URI;

public final class FormConfiguration implements Configuration {

    private final PasswordRequestAuthenticator authenticator;
    private final URI customLoginFormUri;
    private final String usernameField;
    private final String passwordField;
    private final String contextField;

    FormConfiguration(PasswordRequestAuthenticator authenticator, URI customLoginFormUri, String usernameField, String passwordField, String contextField) {
        this.authenticator = authenticator;
        this.customLoginFormUri = customLoginFormUri;
        this.usernameField = usernameField;
        this.passwordField = passwordField;
        this.contextField = contextField;
    }

    public PasswordRequestAuthenticator getAuthenticator() {
        return authenticator;
    }

    public URI getCustomLoginFormUri() {
        return customLoginFormUri;
    }

    public String getUsernameField() {
        return usernameField;
    }

    public String getPasswordField() {
        return passwordField;
    }

    public String getContextField() {
        return contextField;
    }
}

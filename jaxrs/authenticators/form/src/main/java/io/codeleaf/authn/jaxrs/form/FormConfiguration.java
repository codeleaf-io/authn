package io.codeleaf.authn.jaxrs.form;

import io.codeleaf.authn.password.spi.PasswordRequestAuthenticator;
import io.codeleaf.config.Configuration;

import java.net.URI;

public final class FormConfiguration implements Configuration {

    private final PasswordRequestAuthenticator authenticator;
    private final URI customLoginFormUri;
    private final URI customLandingPageUri;
    private final String usernameField;
    private final String passwordField;

    FormConfiguration(PasswordRequestAuthenticator authenticator, URI customLoginFormUri, URI customLandingPageUri, String usernameField, String passwordField) {
        this.authenticator = authenticator;
        this.customLoginFormUri = customLoginFormUri;
        this.customLandingPageUri = customLandingPageUri;
        this.usernameField = usernameField;
        this.passwordField = passwordField;
    }

    public PasswordRequestAuthenticator getAuthenticator() {
        return authenticator;
    }

    public URI getCustomLoginFormUri() {
        return customLoginFormUri;
    }

    public URI getCustomLandingPageUri() {
        return customLandingPageUri;
    }

    public String getUsernameField() {
        return usernameField;
    }

    public String getPasswordField() {
        return passwordField;
    }
}

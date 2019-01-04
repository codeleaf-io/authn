package io.codeleaf.authn.jaxrs.basic;

import javax.security.auth.Subject;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.login.LoginException;
import java.security.AuthProvider;

public class BasicAuthenticationProvider extends AuthProvider {

    private CallbackHandler callbackHandler;

    /**
     * Constructs a provider with the specified name, version number,
     * and information.
     *
     * @param name    the provider name.
     * @param version the provider version number.
     * @param info    a description of the provider and its services.
     */
    protected BasicAuthenticationProvider(String name, double version, String info) {
        super(name, version, info);
    }

    protected BasicAuthenticationProvider(String name, double version, String info, CallbackHandler callbackHandler) {
        super(name, version, info);
        this.callbackHandler = callbackHandler;
    }

    public void login(Subject subject, CallbackHandler handler) throws LoginException {

    }

    public void logout() throws LoginException {

    }

    public void setCallbackHandler(CallbackHandler handler) {
        this.callbackHandler = handler;
    }
}

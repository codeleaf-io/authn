package io.codeleaf.authn.jaxrs.basic;

import io.codeleaf.authn.AuthenticationContext;
import io.codeleaf.authn.AuthenticationException;
import io.codeleaf.authn.jaxrs.spi.JaxrsRequestAuthenticator;
import io.codeleaf.authn.password.spi.PasswordRequestAuthenticator;

import javax.ws.rs.container.ContainerRequestContext;
import java.util.Base64;

public final class BasicJaxrsRequestAuthenticator implements JaxrsRequestAuthenticator {

    private static final String HEADER_VALUE_PREFIX = "Basic ";
    private static final String HEADER_KEY = "Authorization";
    private final PasswordRequestAuthenticator passwordRequestAuthenticator;

    public BasicJaxrsRequestAuthenticator(PasswordRequestAuthenticator passwordRequestAuthenticator) {
        this.passwordRequestAuthenticator = passwordRequestAuthenticator;
    }

    @Override
    public AuthenticationContext authenticate(ContainerRequestContext requestContext) throws AuthenticationException {
        String basicAuthnHeaderValue = requestContext.getHeaderString(HEADER_KEY);
        AuthenticationContext authenticationContext = null;

        if (basicAuthnHeaderValue != null && !basicAuthnHeaderValue.isEmpty() && basicAuthnHeaderValue.startsWith(HEADER_VALUE_PREFIX)) {
            String valueDecoded = new String(Base64.getDecoder().decode(basicAuthnHeaderValue.substring(HEADER_VALUE_PREFIX.length() - 1)));
            if (valueDecoded != null && !valueDecoded.isEmpty() && valueDecoded.split(":").length == 2) {
                String[] userPasswordArray = valueDecoded.split(":");
                authenticationContext = passwordRequestAuthenticator.authenticate(userPasswordArray[0], userPasswordArray[1]);
            }
        }
        return authenticationContext;
    }
}
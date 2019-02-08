package io.codeleaf.authn.jaxrs.basic;

import io.codeleaf.authn.AuthenticationContext;
import io.codeleaf.authn.AuthenticationException;
import io.codeleaf.authn.jaxrs.spi.JaxrsRequestAuthenticator;
import io.codeleaf.authn.password.spi.Credentials;
import io.codeleaf.authn.password.spi.PasswordRequestAuthenticator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.ws.rs.container.ContainerRequestContext;
import java.nio.charset.Charset;
import java.util.Base64;
import java.util.Objects;

public final class BasicAuthenticator implements JaxrsRequestAuthenticator {

    private static final Logger LOGGER = LoggerFactory.getLogger(BasicAuthenticator.class);

    private static final Charset UTF8 = Charset.forName("UTF-8");
    private static final String HEADER_VALUE_PREFIX = "Basic ";
    private static final String HEADER_KEY = "Authorization";
    private static final String SEPARATOR = ":";
    private final PasswordRequestAuthenticator passwordRequestAuthenticator;

    public BasicAuthenticator(PasswordRequestAuthenticator passwordRequestAuthenticator) {
        this.passwordRequestAuthenticator = passwordRequestAuthenticator;
    }

    @Override
    public String getAuthenticationScheme() {
        return "BASIC";
    }

    @Override
    public AuthenticationContext authenticate(ContainerRequestContext requestContext, AuthenticatorContext authenticatorContext) throws AuthenticationException {
        Credentials credentials = extractCredentials(requestContext);
        LOGGER.debug("Found credentials: " + (credentials != null));
        return credentials != null ? passwordRequestAuthenticator.authenticate(credentials.getUserName(), credentials.getPassword()) : null;
    }

    private Credentials extractCredentials(ContainerRequestContext requestContext) {
        try {
            Credentials credentials;
            String basicAuthnHeaderValue = requestContext.getHeaderString(HEADER_KEY);
            if (basicAuthnHeaderValue != null && basicAuthnHeaderValue.startsWith(HEADER_VALUE_PREFIX)) {
                byte[] byteSequence = Base64.getDecoder().decode(basicAuthnHeaderValue.substring(HEADER_VALUE_PREFIX.length()));
                String decodedValue = new String(byteSequence, UTF8);
                String[] parts = decodedValue.split(SEPARATOR);
                credentials = parts.length == 2 ? Credentials.createOrNull(parts[0], parts[1]) : null;
            } else {
                credentials = null;
            }
            return credentials;
        } catch (IllegalArgumentException cause) {
            LOGGER.warn(cause.getMessage());
            return null;
        }
    }

    public static BasicAuthenticator create(BasicConfiguration configuration) {
        Objects.requireNonNull(configuration);
        return new BasicAuthenticator(configuration.getAuthenticator());
    }
}
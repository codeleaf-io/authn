package io.codeleaf.authn.password.dummy;

import io.codeleaf.authn.AuthenticationContext;
import io.codeleaf.authn.impl.DefaultAuthenticationContext;
import io.codeleaf.authn.password.spi.Credentials;
import io.codeleaf.authn.password.spi.PasswordRequestAuthenticator;
import io.codeleaf.config.ConfigurationException;
import io.codeleaf.config.ConfigurationProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.util.Objects;

public final class DummyAuthenticator implements PasswordRequestAuthenticator {

    private static final Logger LOGGER = LoggerFactory.getLogger(DummyAuthenticator.class);

    private final String userName;
    private final String password;

    private DummyAuthenticator(String userName, String password) {
        this.userName = userName;
        this.password = password;
    }

    @Override
    public AuthenticationContext authenticate(Credentials credentials) {
        boolean matches = true;
        if (!userName.equals(credentials.getUserName())) {
            LOGGER.debug("Username not matching!");
            matches = false;
        }
        if (!password.equals(credentials.getPassword())) {
            LOGGER.debug("Password not matching!");
            matches = false;
        }
        if (matches) {
            LOGGER.debug("Correct credentials");
        }
        return matches ? DefaultAuthenticationContext.create(userName) : null;
    }

    public DummyAuthenticator() throws ConfigurationException, IOException {
        this(ConfigurationProvider.get().getConfiguration(DummyConfiguration.class));
    }

    public DummyAuthenticator(DummyConfiguration dummyConfiguration) {
        this(dummyConfiguration.getUserName(), dummyConfiguration.getPassword());
    }

    public static DummyAuthenticator create(String userName, String password) {
        Objects.requireNonNull(userName);
        Objects.requireNonNull(password);
        return new DummyAuthenticator(userName, password);
    }

    public static DummyAuthenticator create(DummyConfiguration configuration) {
        Objects.requireNonNull(configuration);
        return new DummyAuthenticator(configuration);
    }
}
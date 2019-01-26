package io.codeleaf.authn.password.spi;

import java.util.Objects;

public class Credentials {

    private final String userName;
    private final String password;

    protected Credentials(String userName, String password) {
        this.userName = userName;
        this.password = password;
    }

    public String getUserName() {
        return userName;
    }

    public String getPassword() {
        return password;
    }

    public static Credentials createOrNull(String userName, String password) {
        if (userName == null || userName.isEmpty() || password == null || password.isEmpty()) {
            return null;
        }
        return new Credentials(userName, password);
    }

    public static Credentials create(String userName, String password) {
        Objects.requireNonNull(userName);
        Objects.requireNonNull(password);
        return new Credentials(userName, password);
    }
}

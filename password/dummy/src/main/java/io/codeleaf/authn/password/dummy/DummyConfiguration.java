package io.codeleaf.authn.password.dummy;

import io.codeleaf.config.Configuration;

public final class DummyConfiguration implements Configuration {

    private final String userName;
    private final String password;

    DummyConfiguration(String userName, String password) {
        this.userName = userName;
        this.password = password;
    }

    public String getUserName() {
        return userName;
    }

    public String getPassword() {
        return password;
    }

    private static final DummyConfiguration DEFAULT = new DummyConfiguration("dummy", "dummy");

    public static DummyConfiguration getDefault() {
        return DEFAULT;
    }
}

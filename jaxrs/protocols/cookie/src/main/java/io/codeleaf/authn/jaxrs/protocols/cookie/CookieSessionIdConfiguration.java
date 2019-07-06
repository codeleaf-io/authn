package io.codeleaf.authn.jaxrs.protocols.cookie;

import io.codeleaf.config.Configuration;

public final class CookieSessionIdConfiguration implements Configuration {

    private final String name;
    private final String path;
    private final String domain;
    private final String comment;
    private final int maxAge;
    private final boolean secure;
    private final boolean httpOnly;

    CookieSessionIdConfiguration(String name, String path, String domain, String comment, int maxAge, boolean secure, boolean httpOnly) {
        this.name = name;
        this.path = path;
        this.domain = domain;
        this.comment = comment;
        this.maxAge = maxAge;
        this.secure = secure;
        this.httpOnly = httpOnly;
    }

    public String getName() {
        return name;
    }

    public String getPath() {
        return path;
    }

    public String getDomain() {
        return domain;
    }

    public String getComment() {
        return comment;
    }

    public int getMaxAge() {
        return maxAge;
    }

    public boolean isSecure() {
        return secure;
    }

    public boolean isHttpOnly() {
        return httpOnly;
    }
}

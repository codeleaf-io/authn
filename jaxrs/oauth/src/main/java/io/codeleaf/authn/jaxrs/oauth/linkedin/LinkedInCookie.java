package io.codeleaf.authn.jaxrs.oauth.linkedin;

import com.github.scribejava.core.model.OAuth2AccessToken;

import javax.ws.rs.core.NewCookie;
import java.util.HashMap;
import java.util.Map;

public final class LinkedInCookie extends NewCookie {

    public static final String COOKIE_NAME = "DATA";
    public static final String TOKEN = "TOKEN";
    public static final String REFRESH_TOKEN = "REFRESH_TOKEN";
    public static final String SCOPE = "SCOPE";
    public static final String TOKEN_TYPE = "TOKEN_TYPE";
    public static final String EXPIRES_IN = "EXPIRES_IN";

    private final String token;
    private final String refreshToken;
    private final String scope;
    private final String tokenType;
    private final Integer expiresIn;

    public LinkedInCookie(String token, String refreshToken, String scope, String tokenType, Integer expiresIn) {
        super(COOKIE_NAME, StringMapUtil.encodeString(token, refreshToken, scope, tokenType, expiresIn.toString()), "/", null, NewCookie.DEFAULT_VERSION, null, NewCookie.DEFAULT_MAX_AGE, null, true, true);
        this.token = token;
        this.refreshToken = refreshToken;
        this.scope = scope;
        this.tokenType = tokenType;
        this.expiresIn = expiresIn;
    }

    public LinkedInCookie(String value) {
        super(COOKIE_NAME, value, "/", null, NewCookie.DEFAULT_VERSION, null, NewCookie.DEFAULT_MAX_AGE, null, true, true);
        Map<String, String> map = StringMapUtil.decodeString(value);
        this.token = map.get(TOKEN);
        this.refreshToken = map.get(REFRESH_TOKEN);
        this.scope = map.get(SCOPE);
        this.tokenType = map.get(TOKEN_TYPE);
        this.expiresIn = Integer.parseInt(map.get(EXPIRES_IN));
    }

    public LinkedInCookie(OAuth2AccessToken accessToken) {
        super(COOKIE_NAME, StringMapUtil.encodeString(toStringMap(accessToken)), "/", null, NewCookie.DEFAULT_VERSION, null, NewCookie.DEFAULT_MAX_AGE, null, true, true);
        this.token = accessToken.getAccessToken();
        this.refreshToken = accessToken.getRefreshToken();
        this.scope = accessToken.getScope();
        this.tokenType = accessToken.getTokenType();
        this.expiresIn = accessToken.getExpiresIn();
    }

    private static Map<String, String> toStringMap(OAuth2AccessToken accessToken) {
        Map<String, String> stringMap = new HashMap<>();
        stringMap.put(TOKEN, accessToken.getAccessToken());
        stringMap.put(REFRESH_TOKEN, accessToken.getRefreshToken());
        stringMap.put(SCOPE, accessToken.getScope());
        stringMap.put(TOKEN_TYPE, accessToken.getTokenType());
        stringMap.put(EXPIRES_IN, accessToken.getExpiresIn().toString());
        return stringMap;
    }

    public String getToken() {
        return token;
    }

    public String getRefreshToken() {
        return refreshToken;
    }

    public String getScope() {
        return scope;
    }

    public String getTokenType() {
        return tokenType;
    }

    public Integer getExpiresIn() {
        return expiresIn;
    }
}

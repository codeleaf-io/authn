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

    private LinkedInCookie(String token, String refreshToken, String scope, String tokenType, Integer expiresIn) {
        super(COOKIE_NAME, StringMapUtil.encodeString(toStringMap(token, refreshToken, scope, tokenType, expiresIn)), "/", "", NewCookie.DEFAULT_VERSION, null, NewCookie.DEFAULT_MAX_AGE, null, true, true);
        this.token = token;
        this.refreshToken = refreshToken;
        this.scope = scope;
        this.tokenType = tokenType;
        this.expiresIn = expiresIn;
    }

    private static Map<String, String> toStringMap(String token, String refreshToken, String scope, String tokenType, Integer expiresIn) {
        Map<String, String> stringMap = new HashMap<>();
        stringMap.put(TOKEN, token);
        stringMap.put(REFRESH_TOKEN, refreshToken);
        stringMap.put(SCOPE, scope);
        stringMap.put(TOKEN_TYPE, tokenType);
        stringMap.put(EXPIRES_IN, expiresIn.toString());
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

    public static final class Factory {

        public static final LinkedInCookie create(OAuth2AccessToken accessToken) {
            return new LinkedInCookie(accessToken.getAccessToken(),
                    accessToken.getRefreshToken(),
                    accessToken.getScope(),
                    accessToken.getTokenType(),
                    accessToken.getExpiresIn());
        }

        public static final LinkedInCookie create(String value) {
            Map<String, String> map = StringMapUtil.decodeString(value);
            return new LinkedInCookie(map.get(TOKEN),
                    map.get(REFRESH_TOKEN),
                    map.get(SCOPE),
                    map.get(TOKEN_TYPE),
                    Integer.parseInt(map.get(EXPIRES_IN)));
        }
    }
}

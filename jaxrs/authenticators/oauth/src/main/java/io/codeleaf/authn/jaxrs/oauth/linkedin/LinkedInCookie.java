package io.codeleaf.authn.jaxrs.oauth.linkedin;

import com.github.scribejava.core.model.OAuth2AccessToken;
import io.codeleaf.common.utils.StringEncoder;

import javax.servlet.http.Cookie;
import javax.ws.rs.core.NewCookie;
import java.io.UnsupportedEncodingException;
import java.util.HashMap;
import java.util.Map;

public final class LinkedInCookie extends NewCookie {

    public static final String COOKIE_NAME = "DATA";

    public static final String FIRST_NAME = "FIRST_NAME";
    public static final String LAST_NAME = "LAST_NAME";
    public static final String HEADLINE = "HEADLINE";

    public static final String TOKEN = "TOKEN";
    public static final String REFRESH_TOKEN = "REFRESH_TOKEN";
    public static final String SCOPE = "SCOPE";
    public static final String TOKEN_TYPE = "TOKEN_TYPE";
    public static final String EXPIRES_IN = "EXPIRES_IN";
    public static final String LANDING_PAGE_URL = "LANDING_PAGE_URL";

    private final String token;
    private final String refreshToken;
    private final String scope;
    private final String tokenType;
    private final Integer expiresIn;
    private final String firstName;
    private final String lastName;
    private final String headline;
    private final String cookieDomain;
    private final String landingPageUrl;

    private LinkedInCookie(String firstName, String lastName, String headline, String token, String refreshToken, String scope, String tokenType, Integer expiresIn, String cookieDomain, String landingPageUrl) throws UnsupportedEncodingException {
        super(COOKIE_NAME,
                StringEncoder.toEncodedBase64UTF8(StringEncoder.encodeMap(toStringMap(firstName, lastName, headline, token, refreshToken, scope, tokenType, expiresIn))),
                "/", cookieDomain, NewCookie.DEFAULT_VERSION, null, -1, null, false, true);
        this.token = token;
        this.refreshToken = refreshToken;
        this.scope = scope;
        this.tokenType = tokenType;
        this.expiresIn = expiresIn;
        this.firstName = firstName;
        this.lastName = lastName;
        this.headline = headline;
        this.cookieDomain = cookieDomain;
        this.landingPageUrl = landingPageUrl;
    }

    private static Map<String, String> toStringMap(String firstName, String lastName, String headline, String token, String refreshToken, String scope, String tokenType, Integer expiresIn) {
        Map<String, String> stringMap = new HashMap<>();
        stringMap.put(FIRST_NAME, firstName);
        stringMap.put(LAST_NAME, lastName);
        stringMap.put(HEADLINE, headline);
        stringMap.put(TOKEN, token);
        stringMap.put(REFRESH_TOKEN, refreshToken);
        stringMap.put(SCOPE, scope);
        stringMap.put(TOKEN_TYPE, tokenType);
        stringMap.put(EXPIRES_IN, expiresIn.toString());
        return stringMap;
    }

    public static Cookie eraseCookieData(Cookie[] cookies) {
        if (cookies != null) {
            for (Cookie cookie : cookies) {
                if (cookie.getName().equals(COOKIE_NAME)) {
                    cookie.setValue("");
                    cookie.setPath("/");
                    cookie.setMaxAge(0);
                    return cookie;
                }
            }
        }
        return null;
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

    public String getFirstName() {
        return firstName;
    }

    public String getLastName() {
        return lastName;
    }

    public String getHeadline() {
        return headline;
    }

    public String getCookieDomain() {
        return cookieDomain;
    }

    public static final class Factory {

        private Factory() {
        }

        public static LinkedInCookie create(OAuth2AccessToken accessToken, String firstName, String lastName, String headline, String cookieDomain, String landingPageUrl) throws UnsupportedEncodingException {
            return new LinkedInCookie(firstName, lastName, headline, accessToken.getAccessToken(),
                    accessToken.getRefreshToken(),
                    accessToken.getScope(),
                    accessToken.getTokenType(),
                    accessToken.getExpiresIn(),
                    cookieDomain,
                    landingPageUrl);
        }

        public static LinkedInCookie create(OAuth2AccessToken accessToken, String cookieDomain, String landingPageUrl) throws UnsupportedEncodingException {
            return new LinkedInCookie(null, null, null, accessToken.getAccessToken(),
                    accessToken.getRefreshToken(),
                    accessToken.getScope(),
                    accessToken.getTokenType(),
                    accessToken.getExpiresIn(),
                    cookieDomain,
                    landingPageUrl);
        }

        public static LinkedInCookie create(String value, String cookieDomain) throws UnsupportedEncodingException {
            Map<String, String> map = StringEncoder.decodeMap(StringEncoder.toDecodedBase64UTF8(value));
            return new LinkedInCookie(map.get(FIRST_NAME),
                    map.get(LAST_NAME),
                    map.get(HEADLINE),
                    map.get(TOKEN),
                    map.get(REFRESH_TOKEN),
                    map.get(SCOPE),
                    map.get(TOKEN_TYPE),
                    Integer.parseInt(map.get(EXPIRES_IN)),
                    cookieDomain,
                    map.get(LANDING_PAGE_URL));
        }
    }
}

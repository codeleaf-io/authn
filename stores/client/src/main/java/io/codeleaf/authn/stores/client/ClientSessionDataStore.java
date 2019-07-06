package io.codeleaf.authn.stores.client;

import io.codeleaf.authn.spi.SessionDataStore;
import io.codeleaf.common.utils.AES1;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;

import javax.crypto.spec.SecretKeySpec;
import java.security.Key;
import java.util.Date;

public final class ClientSessionDataStore implements SessionDataStore {

    private final Key key;
    private final ClientSessionDataConfiguration configuration;
    private final SecretKeySpec secretKeySpec;

    public static ClientSessionDataStore create(ClientSessionDataConfiguration configuration) {
        return new ClientSessionDataStore(
                Keys.secretKeyFor(SignatureAlgorithm.HS256),
                configuration,
                configuration.isEncrypted() ? AES1.createSecretKey(configuration.getSecret()) : null);
    }

    private ClientSessionDataStore(Key key, ClientSessionDataConfiguration configuration, SecretKeySpec secretKeySpec) {
        this.key = key;
        this.configuration = configuration;
        this.secretKeySpec = secretKeySpec;
    }

    @Override
    public String storeSessionData(String sessionData) {
        return Jwts.builder()
                .setSubject(configuration.isEncrypted() ? encrypt(sessionData) : sessionData)
                .setIssuedAt(new Date())
                .signWith(key)
                .compact();
    }

    @Override
    public String retrieveSessionData(String sessionId) {
        try {
            Claims claims = Jwts.parser().setSigningKey(key).parseClaimsJws(sessionId).getBody();
            return isTimedOut(claims.getIssuedAt()) ? null :
                    configuration.isEncrypted() ? decrypt(claims.getSubject()) : claims.getSubject();
        } catch (JwtException cause) {
            System.err.println(cause);
            return null;
        }
    }

    private boolean isTimedOut(Date issuedAt) {
        boolean timedOut = System.currentTimeMillis() - issuedAt.getTime() >= configuration.getTimeoutTime() * 1_000;
        if (timedOut) {
            System.err.println("jwt is timed out!");
        }
        return timedOut;
    }

    private String encrypt(String sessionData) {
        return AES1.encrypt(sessionData, secretKeySpec);
    }

    private String decrypt(String encryptedSessionData) {
        return AES1.decrypt(encryptedSessionData, secretKeySpec);
    }
}

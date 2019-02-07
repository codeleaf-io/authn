package io.codeleaf.authn.stores.local;

import io.codeleaf.authn.spi.SessionDataStore;

import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

public final class LocalSessionDataStore implements SessionDataStore {

    private final Map<String, String> sessionDataStore = new HashMap<>();

    @Override
    public String storeSessionData(String sessionData) {
        String sessionId = UUID.randomUUID().toString();
        sessionDataStore.put(sessionId, sessionData);
        return sessionId;
    }

    @Override
    public String retrieveSessionData(String sessionId) {
        return sessionDataStore.get(sessionId);
    }
}

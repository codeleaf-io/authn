package io.codeleaf.authn.spi;

public interface SessionDataStore {

    String storeSessionData(String sessionData);

    String retrieveSessionData(String sessionId);
}

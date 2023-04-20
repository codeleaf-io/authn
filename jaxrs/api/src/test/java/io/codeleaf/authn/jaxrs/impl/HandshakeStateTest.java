package io.codeleaf.authn.jaxrs.impl;

import io.codeleaf.authn.jaxrs.spi.HandshakeState;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.net.URI;

public class HandshakeStateTest {

    @Test
    public void testDecode() {
        // Given
        HandshakeState state = new HandshakeState(URI.create("abc:def/ghi"));
        state.getAuthenticatorNames().add("foo,");
        state.getAuthenticatorNames().add("bar");
        String encodedHandshakeState = state.encode();

        // When
        HandshakeState result = HandshakeState.decode(encodedHandshakeState);

        // Then
        Assertions.assertEquals("abc:def/ghi", state.getUri().toString());
        Assertions.assertEquals(2, state.getAuthenticatorNames().size());
        Assertions.assertTrue(state.getAuthenticatorNames().contains("foo,"));
        Assertions.assertTrue(state.getAuthenticatorNames().contains("bar"));
    }

}

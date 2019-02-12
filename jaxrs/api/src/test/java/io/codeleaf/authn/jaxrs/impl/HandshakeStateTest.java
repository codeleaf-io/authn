package io.codeleaf.authn.jaxrs.impl;

import org.junit.Assert;
import org.junit.Test;

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
        Assert.assertEquals("abc:def/ghi", state.getUri().toString());
        Assert.assertEquals(2, state.getAuthenticatorNames().size());
        Assert.assertTrue(state.getAuthenticatorNames().contains("foo,"));
        Assert.assertTrue(state.getAuthenticatorNames().contains("bar"));
    }

}

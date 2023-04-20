package io.codeleaf.authn.stores.client.jsonp;

import io.jsonwebtoken.io.SerializationException;
import io.jsonwebtoken.io.Serializer;
import io.jsonwebtoken.lang.Assert;
import jakarta.json.JsonException;
import jakarta.json.bind.Jsonb;
import jakarta.json.bind.JsonbBuilder;
import jakarta.json.bind.JsonbException;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

public final class JsonbSerializer<T> implements Serializer<T> {

    private final Jsonb jsonb;

    public JsonbSerializer() {
        this(JsonbBuilder.create());
    }

    private JsonbSerializer(Jsonb jsonb) {
        Assert.notNull(jsonb, "Jsonb cannot be null.");
        this.jsonb = jsonb;
    }

    @Override
    public byte[] serialize(T t) throws SerializationException {
        Assert.notNull(t, "Object to serialize cannot be null.");
        try (ByteArrayOutputStream baos = new ByteArrayOutputStream()) {
            jsonb.toJson(t, baos);
            return baos.toByteArray();
        } catch (IOException | JsonException | JsonbException cause) {
            String msg = "Unable to serialize object: " + cause.getMessage();
            throw new SerializationException(msg, cause);
        }
    }
}

package io.codeleaf.authn.stores.client.jsonp;

import io.jsonwebtoken.io.DeserializationException;
import io.jsonwebtoken.io.Deserializer;
import io.jsonwebtoken.lang.Assert;
import jakarta.json.JsonException;
import jakarta.json.bind.Jsonb;
import jakarta.json.bind.JsonbBuilder;
import jakarta.json.bind.JsonbException;

import java.io.ByteArrayInputStream;

public final class JsonbDeserializer<T> implements Deserializer<T> {

    private final Jsonb jsonb;
    private final Class<T> returnType;

    public JsonbDeserializer() {
        this(JsonbBuilder.create());
    }

    @SuppressWarnings("unchecked")
    public JsonbDeserializer(Jsonb jsonb) {
        this(jsonb, (Class<T>) Object.class);
    }

    private JsonbDeserializer(Jsonb jsonb, Class<T> returnType) {
        Assert.notNull(jsonb, "Jsonb cannot be null.");
        Assert.notNull(returnType, "Return type cannot be null.");
        this.jsonb = jsonb;
        this.returnType = returnType;
    }

    @Override
    public T deserialize(byte[] bytes) throws DeserializationException {
        try {
            return jsonb.fromJson(new ByteArrayInputStream(bytes), returnType);
        } catch (JsonException | JsonbException cause) {
            String msg = "Unable to deserialize bytes into a " + this.returnType.getName() + " instance: " + cause.getMessage();
            throw new DeserializationException(msg, cause);
        }
    }

}
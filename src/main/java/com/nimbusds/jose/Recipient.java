package com.nimbusds.jose;

import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jose.util.JSONObjectUtils;

import java.text.ParseException;
import java.util.*;

public class Recipient {
    /**
     * The registered parameter names.
     */
    private static final Set<String> REGISTERED_PARAMETER_NAMES;

    /*
     * Initialises the registered parameter name set.
     */
    static {
        Set<String> p = new HashSet<>();

        p.add(HeaderParameterNames.ALGORITHM);
        p.add(HeaderParameterNames.KEY_ID);

        REGISTERED_PARAMETER_NAMES = Collections.unmodifiableSet(p);
    }

    /**
     * Gets the registered parameter names for JWE headers.
     *
     * @return The registered parameter names, as an unmodifiable set.
     */
    public static Set<String> getRegisteredParameterNames() {

        return REGISTERED_PARAMETER_NAMES;
    }

    private final Base64URL encryptedKey;
    private Map<String, Object> header;

    protected Recipient(Map<String, Object> header, Base64URL encryptedKey) {
        if (header != null && !header.isEmpty()) {
            this.header = header;
        }

        this.encryptedKey = encryptedKey;
    }

    public Map<String, Object> getHeader() {
        return header;
    }

    public Base64URL getEncryptedKey() {
        return encryptedKey;
    }

    public Map<String, Object> toJSONObject() {
        Map<String, Object> json = new HashMap<>();

        if (getHeader() != null) {
            json.put("header", getHeader());
        }

        if (getEncryptedKey() != null) {
            json.put("encrypted_key", getEncryptedKey().toString());
        }

        return json;
    }

    public static Recipient parse(Map<String, Object> json) throws ParseException {
        Map<String, Object> header = JSONObjectUtils.getJSONObject(json, "header");
        return new Builder()
                .kid(JSONObjectUtils.getString(header, "kid"))
                .encryptedKey(JSONObjectUtils.getBase64URL(json, "encrypted_key"))
                .build();
    }

    public static class Builder {
        private final Map<String, Object> header = new HashMap<>();
        private Base64URL encryptedKey;

        public Builder kid(String kid) {
            header.put("kid", kid);
            return this;
        }

        public Builder encryptedKey(Base64URL encryptedKey) {
            this.encryptedKey = encryptedKey;
            return this;
        }

        /**
         * Sets a custom (non-registered) parameter.
         *
         * @param name  The name of the custom parameter. Must not
         *              match a registered parameter name and must not
         *              be {@code null}.
         * @param value The value of the custom parameter, should map
         *              to a valid JSON entity, {@code null} if not
         *              specified.
         *
         * @return This builder.
         *
         * @throws IllegalArgumentException If the specified parameter
         *                                  name matches a registered
         *                                  parameter name.
         */
        public Builder customParam(final String name, final Object value) {

            if (getRegisteredParameterNames().contains(name)) {
                throw new IllegalArgumentException("The parameter name \"" + name + "\" matches a registered name");
            }

            header.put(name, value);

            return this;
        }

        public Recipient build() {
            return new Recipient(header, encryptedKey);
        }
    }
}

package com.nimbusds.jose;

import com.nimbusds.jose.util.JSONObjectUtils;
import net.minidev.json.JSONObject;

import java.text.ParseException;
import java.util.*;

public class UnprotectedHeader {
    /**
     * The registered parameter names.
     */
    private static final Set<String> REGISTERED_PARAMETER_NAMES;

    /*
     * Initialises the registered parameter name set.
     */
    static {
        Set<String> p = new HashSet<>();

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

    private final Map<String, Object> header;

    protected UnprotectedHeader(Map<String, Object> header) {
        this.header = header;
    }

    /**
     * Returns Unprotected Header
     * might be {@code null} if is not specified.
     *
     * @return Unprotected Header
     */
    public String getKeyID() {
        return (String) header.get(HeaderParameterNames.KEY_ID);
    }

    /**
     * Returns JSON object. Might be empty if
     * header and encryption_key are not specified.
     *
     *
     * @return JSON object
     */
    public JSONObject toJSONObject() {
        Map<String, Object> o = JSONObjectUtils.newJSONObject();

        o.putAll(header);

        return new JSONObject(o);
    }

    public static UnprotectedHeader parse(Map<String, Object> jsonObject) throws ParseException {
        Builder header = new Builder();

        if (jsonObject == null) {
            return null;
        }

        for(final String name: jsonObject.keySet()) {
            if(HeaderParameterNames.KEY_ID.equals(name)) {
                header = header.keyID(JSONObjectUtils.getString(jsonObject, name));
            } else {
                header = header.customParam(name, jsonObject.get(name));
            }
        }

        return header.build();
    }

    /**
     * Unprotected Header Builder
     */
    public static class Builder {
        private final Map<String, Object> header = new HashMap<>();

        /**
         * Sets the key ID ({@code kid}) parameter.
         *
         * @param kid The key ID parameter, {@code null} if not
         *            specified.
         *
         * @return This builder.
         */
        public Builder keyID(String kid) {
            header.put(HeaderParameterNames.KEY_ID, kid);
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

        /**
         * Build new {@link Recipient}
         *
         * @return recipient
         */
        public UnprotectedHeader build() {
            return new UnprotectedHeader(header);
        }
    }
}

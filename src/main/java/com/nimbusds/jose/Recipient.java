/*
 * nimbus-jose-jwt
 *
 * Copyright 2012-2021, Connect2id Ltd and contributors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use
 * this file except in compliance with the License. You may obtain a copy of the
 * License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed
 * under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
 * CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 */

package com.nimbusds.jose;

import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jose.util.JSONObjectUtils;

import java.text.ParseException;
import java.util.*;

/**
 * Create Recipient object
 *
 * see https://datatracker.ietf.org/doc/html/rfc7516#section-7.2
 *
 * @author Alexander Martynov
 * @version 2021-08-19
 */
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

    /**
     * Returns JWE Per-Recipient Unprotected Header
     * might be {@code null} if is not specified.
     *
     * @return JWE Per-Recipient Unprotected Header
     */
    public Map<String, Object> getHeader() {
        return header;
    }

    /**
     * Returns Recipient Encryption Key
     * might be {@code null}.
     *
     * @return encryption key
     */
    public Base64URL getEncryptedKey() {
        return encryptedKey;
    }

    /**
     * Returns JSON object. Might be empty if
     * header and encryption_key are not specified.
     *
     *
     * @return JSON object
     */
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

    /**
     * Creates new Recipient object
     *
     * @param json The string to parse. Must not be {@code null}.
     * @return Recipient object
     * @throws ParseException If parsing of the serialised parts failed.
     */
    public static Recipient parse(Map<String, Object> json) throws ParseException {
        Map<String, Object> header = JSONObjectUtils.getJSONObject(json, "header");
        return new Builder()
                .kid(JSONObjectUtils.getString(header, "kid"))
                .encryptedKey(JSONObjectUtils.getBase64URL(json, "encrypted_key"))
                .build();
    }

    /**
     * Creates new array of Recipient objects
     *
     * @param jsonArray The string to parse. Must not be {@code null}.
     *
     * @return Array recipients
     * @throws ParseException If parsing of the serialised parts failed.
     */
    public static List<Recipient> parse(Map<String, Object>[] jsonArray) throws ParseException {
        List<Recipient> recipients = new ArrayList<>();

        if (jsonArray != null) {
            for (Map<String, Object> json : jsonArray) {
                recipients.add(parse(json));
            }
        }

        return recipients;
    }

    /**
     * Recipient Builder
     */
    public static class Builder {
        private final Map<String, Object> header = new HashMap<>();
        private Base64URL encryptedKey;

        /**
         * Sets the key ID ({@code kid}) parameter.
         *
         * @param kid The key ID parameter, {@code null} if not
         *            specified.
         *
         * @return This builder.
         */
        public Builder kid(String kid) {
            header.put("kid", kid);
            return this;
        }

        /**
         * Sets the key ID ({@code encryptedKey}) parameter.
         *
         * @param encryptedKey  The encryptedKey parameter,
         *                      {@code null} if not specified.
         *
         * @return This builder.
         */
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

        /**
         * Build new {@link Recipient}
         *
         * @return recipient
         */
        public Recipient build() {
            return new Recipient(header, encryptedKey);
        }
    }
}

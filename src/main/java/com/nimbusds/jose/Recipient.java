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

    private final Base64URL encryptedKey;
    private UnprotectedHeader header = null;

    public Recipient(UnprotectedHeader header, Base64URL encryptedKey) {
        if (header != null) {
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
    public UnprotectedHeader getHeader() {
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
            json.put("header", getHeader().toJSONObject());
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
        UnprotectedHeader header = UnprotectedHeader.parse(JSONObjectUtils.getJSONObject(json, "header"));
        Base64URL encryptedKey = JSONObjectUtils.getBase64URL(json, "encrypted_key");
        return new Recipient(header, encryptedKey);
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
}

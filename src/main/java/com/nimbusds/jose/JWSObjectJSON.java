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
import net.jcip.annotations.ThreadSafe;

import java.nio.charset.StandardCharsets;
import java.text.ParseException;
import java.util.*;


/**
 * JSON Web Signature (JWS) secured object.
 *
 * Provides <a href="https://datatracker.ietf.org/doc/html/rfc7515#section-3.2">JSON JWS Serialization</a>
 *
 * This class is thread-safe.
 *
 * @author Alexander Martynov
 * @version 2021-08-17
 */
@ThreadSafe
public class JWSObjectJSON extends JWSObject implements JSONSerializable {

    private static final long serialVersionUID = 1L;

    /**
     * Unprotected Per-Signature headers.
     * Now support only one signature.
     */
    private UnprotectedHeader unprotectedHeader;

    /**
     * Creates a new to-be-signed JSON Web Signature (JWS) object with the
     * specified header and payload. The initial state will be
     * {@link State#UNSIGNED unsigned}.
     *
     * @param header  The JWS header. Must not be {@code null}.
     * @param payload The payload. Must not be {@code null}.
     */
    public JWSObjectJSON(JWSHeader header, Payload payload) {
        super(header, payload);
    }

    /**
     * Creates a new signed JSON Web Signature (JWS) object with the
     * specified serialised parts. The state will be
     * {@link State#SIGNED signed}.
     *
     * @param protectedHeader   The protected JWS header.
     *                          Must not be {@code null}.
     * @param unprotectedHeader The Per-Signature unprotected header.
     *                          Might be {@code null}
     * @param payload           The payload. Must not be {@code null}.
     * @param signature         The signature. Must not be {@code null}.
     *
     * @throws ParseException If parsing of the serialised parts failed.
     */
    public JWSObjectJSON(Base64URL protectedHeader, UnprotectedHeader unprotectedHeader, Base64URL payload, Base64URL signature) throws ParseException {
        super(protectedHeader, payload, signature);

        this.unprotectedHeader = unprotectedHeader;
    }

    /**
     * Returns Per-Signature Unprotected Header.
     * Supports only ONE signature. Might be {@code null}
     *
     * @return Per-Signature Unprotected Header
     */
    public UnprotectedHeader getUnprotectedHeader() {
        return unprotectedHeader;
    }

    @Override
    public Map<String, Object> toJSONObject(boolean flattened) {
        ensureSignedOrVerifiedState();

        Map<String, Object> json = JSONObjectUtils.newJSONObject();

        String signatureStr = getSignature().toString();
        byte[] payload = getPayload().toBytes();
        byte[] header = JSONObjectUtils.toJSONString(getHeader().toJSONObject(), true)
                .getBytes(StandardCharsets.UTF_8);

        if (flattened) {
            json.put("protected", Base64URL.encode(header).toString());
            json.put("payload", Base64URL.encode(payload).toString());
            json.put("signature", signatureStr);
        } else {
            List<Map<String, Object>> signatures = new ArrayList<>();
            Map<String, Object> signature = JSONObjectUtils.newJSONObject();
            signature.put("protected", Base64URL.encode(header).toString());
            signature.put("signature", signatureStr);

            if (unprotectedHeader != null) {
                signature.put("header", unprotectedHeader.toJSONObject());
            }

            signatures.add(signature);

            json.put("payload", Base64URL.encode(payload).toString());
            json.put("signatures", signatures);
        }

        return json;
    }

    /**
     * Serialises this JWS object to JSON format.
     *
     * @return The serialised JWS object.
     *
     * @throws IllegalStateException If the JWS object is not in a
     *                               {@link JWEObjectJSON.State#ENCRYPTED encrypted} or
     *                               {@link JWEObjectJSON.State#DECRYPTED decrypted
     *                               state}.
     */
    @Override
    public String serialize() {

        ensureSignedOrVerifiedState();

        return JSONObjectUtils.toJSONString(toJSONObject(false), true);
    }



    /**
     * Parses a JWS object from the specified string in JSON format. The
     * parsed JWS object will be given a {@link State#SIGNED} state.
     *
     * @param s The JWS string to parse. Must not be {@code null}.
     *
     * @return The JWS object.
     *
     * @throws ParseException If the string couldn't be parsed to a JWS
     *                        object.
     */
    public static JWSObjectJSON parse(String s) throws ParseException {
        Map<String, Object> jsonObject = JSONObjectUtils.parse(s);

        Base64URL signature = JSONObjectUtils.getBase64URL(jsonObject, "signature");
        Base64URL payload = JSONObjectUtils.getBase64URL(jsonObject, "payload");
        Base64URL protectedHeader;
        UnprotectedHeader unprotectedHeader = null;

        boolean flattened = signature != null;

        if (flattened) {
            protectedHeader = JSONObjectUtils.getBase64URL(jsonObject, "protected");
        } else {
            Map<String, Object>[] signatures = JSONObjectUtils.getJSONObjectArray(jsonObject, "signatures");
            if (signatures == null || signatures.length == 0)
                throw new ParseException("Signatures MUST be presented in General JSON Serialization", 0);

            // Supports only one signature in General JSON Serialization
            signature = JSONObjectUtils.getBase64URL(signatures[0], "signature");
            protectedHeader = JSONObjectUtils.getBase64URL(signatures[0], "protected");
            unprotectedHeader = UnprotectedHeader.parse(JSONObjectUtils.getJSONObject(signatures[0], "header"));
        }

        return new JWSObjectJSON(protectedHeader, unprotectedHeader, payload, signature);
    }


    /**
     * Signs this JWS object with the specified signer and unprotected header.
     * The JWS object must be in a {@link State#UNSIGNED unsigned} state.
     *
     * @param header The Per-Signature Unprotected Header.
     * @param signer The JWS signer. Must not be {@code null}.
     *
     * @throws IllegalStateException If the JWS object is not in an
     *                               {@link State#UNSIGNED unsigned state}.
     * @throws JOSEException         If the JWS object couldn't be signed.
     */
    public synchronized void sign(final UnprotectedHeader header, final JWSSigner signer)
            throws JOSEException {

        this.unprotectedHeader = header;
        sign(signer);
    }
}

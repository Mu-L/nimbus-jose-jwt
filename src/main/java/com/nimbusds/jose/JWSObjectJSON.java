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

import java.text.ParseException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;


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

        Map<String, Object> json = new HashMap<>();

        if (flattened) {
            json.put("protected", getHeader().toBase64URL().toString());
            json.put("payload", getPayload().toBase64URL().toString());
            json.put("signature", getSignature().toString());
        } else {
            List<Map<String, Object>> signatures = new ArrayList<>();
            Map<String, Object> signature = new HashMap<>();
            signature.put("protected", getHeader().toBase64URL().toString());
            signature.put("signature", getSignature().toString());

            if (unprotectedHeader != null) {
                signature.put("header", unprotectedHeader.toJSONObject());
            }

            signatures.add(signature);

            json.put("payload", getPayload().toBase64URL().toString());
            json.put("signatures", signatures);
        }

        return json;
    }

    @Override
    public String toString() {
        return JSONObjectUtils.toJSONString(toJSONObject(true));
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
     * Ensures the current state is {@link State#SIGNED signed} or
     * {@link State#VERIFIED verified}.
     *
     * @throws IllegalStateException If the current state is not signed or
     *                               verified.
     */
    private void ensureSignedOrVerifiedState() {

        if (getState() != State.SIGNED && getState() != State.VERIFIED) {

            throw new IllegalStateException("The JWS object must be in a signed or verified state");
        }
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

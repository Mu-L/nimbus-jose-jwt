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
import java.util.HashMap;
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
public class JJWSObject extends JWSObject implements JSONSerializable {

    private static final long serialVersionUID = 1L;

    /**
     * Creates a new to-be-signed JSON Web Signature (JWS) object with the
     * specified header and payload. The initial state will be
     * {@link State#UNSIGNED unsigned}.
     *
     * @param header  The JWS header. Must not be {@code null}.
     * @param payload The payload. Must not be {@code null}.
     */
    public JJWSObject(JWSHeader header, Payload payload) {
        super(header, payload);
    }

    /**
     * Creates a new signed JSON Web Signature (JWS) object with the
     * specified serialised parts. The state will be
     * {@link State#SIGNED signed}.
     *
     * @param protectedHeader  The protected JWS header.
     *                         Must not be {@code null}.
     * @param payload          The payload. Must not be {@code null}.
     * @param signature        The signature. Must not be {@code null}.
     *
     * @throws ParseException If parsing of the serialised parts failed.
     */
    public JJWSObject(Base64URL protectedHeader, Base64URL payload, Base64URL signature) throws ParseException {
        super(protectedHeader, payload, signature);
    }

    @Override
    public Map<String, Object> toJSONObject() {
        ensureSignedOrVerifiedState();

        Map<String, Object> json = new HashMap<>();
        json.put("protected", getHeader().toBase64URL().toString());
        json.put("payload", getPayload().toBase64URL().toString());
        json.put("signature", getSignature().toString());

        return json;
    }

    @Override
    public String toJSONString() {
        return JSONObjectUtils.toJSONString(toJSONObject());
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
    public static JJWSObject parse(String s) throws ParseException {
        Map<String, Object> jsonObject = JSONObjectUtils.parse(s);

        Base64URL protectedHeader = JSONObjectUtils.getBase64URL(jsonObject, "protected");
        Base64URL payload = JSONObjectUtils.getBase64URL(jsonObject, "payload");
        Base64URL signature = JSONObjectUtils.getBase64URL(jsonObject, "signature");

        return new JJWSObject(protectedHeader, payload, signature);
    }
}

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
import sun.reflect.generics.reflectiveObjects.NotImplementedException;

import java.nio.charset.StandardCharsets;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * JSON Web Encryption (JWE) secured object.
 *
 * Provides <a href="https://datatracker.ietf.org/doc/html/rfc7516#section-7.2>JWE JSON Serialization</a>
 *
 * This class is thread-safe.
 *
 * @author Alexander Martynov
 * @version 2021-08-17
 */
@ThreadSafe
public class JWEObjectJSON extends JOSEObject implements JSONSerializable {

    private static final long serialVersionUID = 1L;

    /**
     * Enumeration of the states of a JSON Web Encryption (JWE) object.
     */
    public enum State {


        /**
         * The JWE object is created but not encrypted yet.
         */
        UNENCRYPTED,


        /**
         * The JWE object is encrypted.
         */
        ENCRYPTED,


        /**
         * The JWE object is decrypted.
         */
        DECRYPTED
    }


    /**
     * The header.
     */
    private JWEHeader header;


    /**
     * The recipients, {@code null} if not computed or applicable.
     */
    private List<Recipient> recipients;


    /**
     * The initialisation vector, {@code null} if not generated or 
     * applicable.
     */
    private Base64URL iv;


    /**
     * The cipher text, {@code null} if not computed.
     */
    private Base64URL cipherText;


    /**
     * The authentication tag, {@code null} if not computed or applicable.
     */
    private Base64URL authTag;


    /**
     * The JWE object state.
     */
    private State state;


    /**
     * Creates a new to-be-encrypted JSON Web Encryption (JWE) object with 
     * the specified header and payload. The initial state will be 
     * {@link JWEObjectJSON.State#UNENCRYPTED unencrypted}.
     *
     * @param header  The JWE header. Must not be {@code null}.
     * @param payload The payload. Must not be {@code null}.
     */
    public JWEObjectJSON(final JWEHeader header, final Payload payload) {

        setHeader(header);

        if (payload == null) {

            throw new IllegalArgumentException("The payload must not be null");
        }

        setPayload(payload);

        recipients = null;

        cipherText = null;

        state = JWEObjectJSON.State.UNENCRYPTED;
    }

    /**
     * Creates a new encrypted JSON Web Encryption (JWE) object with the
     * specified serialised parts. The state will be {@link JWEObject.State#ENCRYPTED
     * encrypted}.
     *
     * @param header     The JWE Protected header. Must not be {@code null}.
     * @param recipients The recipients array. Empty or {@code null} if none.
     * @param iv         The initialisation vector. Empty or {@code null} if none.
     * @param ciphertext The cipher text. Must not be {@code null}.
     * @param tag        The authentication tag. Empty of {@code null} if none.
     *
     * @throws ParseException If parsing of the serialised parts failed.
     */
    public JWEObjectJSON(final Base64URL header,
                         final List<Recipient> recipients,
                         final Base64URL iv,
                         final Base64URL ciphertext,
                         final Base64URL tag)
            throws ParseException {

        if (header == null) {

            throw new IllegalArgumentException("The header part must not be null");
        }

        try {
            this.header = JWEHeader.parse(header);

        } catch (ParseException e) {

            throw new ParseException("Invalid JWE header: " + e.getMessage(), 0);
        }

        if (recipients == null || recipients.isEmpty()) {

            this.recipients = null;

        } else {

            this.recipients = recipients;
        }

        if (iv == null || iv.toString().isEmpty()) {

            this.iv = null;

        } else {

            this.iv = iv;
        }

        if (ciphertext == null) {

            throw new IllegalArgumentException("The ciphertext must not be null");
        }

        this.cipherText = ciphertext;

        if (tag == null || tag.toString().isEmpty()) {

            authTag = null;

        } else {

            authTag = tag;
        }

        state = JWEObjectJSON.State.ENCRYPTED; // but not decrypted yet!
    }


    @Override
    public JWEHeader getHeader() {

        return header;
    }


    /**
     * Returns the recipients of this JWE object.
     *
     * @return The recipients, {@code null} if not
     *         applicable or the JWE object has not been encrypted yet.
     */
    public List<Recipient> getRecipients() {

        return recipients;
    }


    /**
     * Returns the initialisation vector (IV) of this JWE object.
     *
     * @return The initialisation vector (IV), {@code null} if not 
     *         applicable or the JWE object has not been encrypted yet.
     */
    public Base64URL getIV() {

        return iv;
    }


    /**
     * Returns the cipher text of this JWE object.
     *
     * @return The cipher text, {@code null} if the JWE object has not been
     *         encrypted yet.
     */
    public Base64URL getCipherText() {

        return cipherText;
    }


    /**
     * Returns the authentication tag of this JWE object.
     *
     * @return The authentication tag, {@code null} if not applicable or
     *         the JWE object has not been encrypted yet.
     */
    public Base64URL getAuthTag() {

        return authTag;
    }


    /**
     * Returns the state of this JWE object.
     *
     * @return The state.
     */
    public JWEObjectJSON.State getState() {

        return state;
    }


    /**
     * Ensures the current state is {@link JWEObjectJSON.State#UNENCRYPTED unencrypted}.
     *
     * @throws IllegalStateException If the current state is not 
     *                               unencrypted.
     */
    private void ensureUnencryptedState() {

        if (state != JWEObjectJSON.State.UNENCRYPTED) {

            throw new IllegalStateException("The JWE object must be in an unencrypted state");
        }
    }


    /**
     * Ensures the current state is {@link JWEObjectJSON.State#ENCRYPTED encrypted}.
     *
     * @throws IllegalStateException If the current state is not encrypted.
     */
    private void ensureEncryptedState() {

        if (state != JWEObjectJSON.State.ENCRYPTED) {

            throw new IllegalStateException("The JWE object must be in an encrypted state");
        }
    }


    /**
     * Ensures the current state is {@link JWEObjectJSON.State#ENCRYPTED encrypted} or
     * {@link JWEObjectJSON.State#DECRYPTED decrypted}.
     *
     * @throws IllegalStateException If the current state is not encrypted 
     *                               or decrypted.
     */
    private void ensureEncryptedOrDecryptedState() {

        if (state != JWEObjectJSON.State.ENCRYPTED && state != JWEObjectJSON.State.DECRYPTED) {

            throw new IllegalStateException("The JWE object must be in an encrypted or decrypted state");
        }
    }


    /**
     * Ensures the specified JWE encrypter supports the algorithms of this 
     * JWE object.
     *
     * @throws JOSEException If the JWE algorithms are not supported.
     */
    private void ensureJWEEncrypterSupport(final JWEEncryptorMulti encrypter)
            throws JOSEException {

        if (! encrypter.supportedJWEAlgorithms().contains(getHeader().getAlgorithm())) {

            throw new JOSEException("The " + getHeader().getAlgorithm() +
                    " algorithm is not supported by the JWE encrypter: Supported algorithms: " + encrypter.supportedJWEAlgorithms());
        }

        if (! encrypter.supportedEncryptionMethods().contains(getHeader().getEncryptionMethod())) {

            throw new JOSEException("The " + getHeader().getEncryptionMethod() +
                    " encryption method or key size is not supported by the JWE encrypter: Supported methods: " + encrypter.supportedEncryptionMethods());
        }
    }


    /**
     * Encrypts this JWE object with the specified encrypter. The JWE 
     * object must be in an {@link JWEObjectJSON.State#UNENCRYPTED unencrypted} state.
     *
     * @param encrypter The JWE encrypter. Must not be {@code null}.
     *
     * @throws IllegalStateException If the JWE object is not in an 
     *                               {@link JWEObjectJSON.State#UNENCRYPTED unencrypted
     *                               state}.
     * @throws JOSEException         If the JWE object couldn't be 
     *                               encrypted.
     */
    public synchronized void encrypt(final JWEEncryptorMulti encrypter)
            throws JOSEException {

        ensureUnencryptedState();

        ensureJWEEncrypterSupport(encrypter);

        JWECryptoParts parts;

        try {
            parts = encrypter.encrypt(getHeader(), getPayload().toBytes());

        } catch (JOSEException e) {

            throw e;

        } catch (Exception e) {

            // Prevent throwing unchecked exceptions at this point,
            // see issue #20
            throw new JOSEException(e.getMessage(), e);
        }

        // Check if the header has been modified
        if (parts.getHeader() != null) {
            header = parts.getHeader();
        }

        recipients = parts.getRecipients();
        iv = parts.getInitializationVector();
        cipherText = parts.getCipherText();
        authTag = parts.getAuthenticationTag();

        state = JWEObjectJSON.State.ENCRYPTED;
    }


    /**
     * Decrypts this JWE object with the specified decrypter. The JWE 
     * object must be in a {@link JWEObjectJSON.State#ENCRYPTED encrypted} state.
     *
     * @param decrypter The JWE decrypter. Must not be {@code null}.
     *
     * @throws IllegalStateException If the JWE object is not in an 
     *                               {@link JWEObjectJSON.State#ENCRYPTED encrypted
     *                               state}.
     * @throws JOSEException         If the JWE object couldn't be 
     *                               decrypted.
     */
    public synchronized void decrypt(final JWEDecrypterMulti decrypter)
            throws JOSEException {

        ensureEncryptedState();

        try {
            setPayload(new Payload(decrypter.decrypt(getHeader(),
                    getRecipients(),
                    getIV(),
                    getCipherText(),
                    getAuthTag())));

        } catch (JOSEException e) {

            throw e;

        } catch (Exception e) {

            // Prevent throwing unchecked exceptions at this point,
            // see issue #20
            throw new JOSEException(e.getMessage(), e);
        }

        state = JWEObjectJSON.State.DECRYPTED;
    }


    /**
     * Serialises this JWE object to JSON format.
     *
     * @return The serialised JWE object.
     *
     * @throws IllegalStateException If the JWS object is not in a
     *                               {@link JWSObject.State#SIGNED signed} or
     *                               {@link JWSObject.State#VERIFIED verified} state.
     */
    @Override
    public String serialize() {

        ensureEncryptedOrDecryptedState();

        return JSONObjectUtils.toJSONString(toJSONObject(false), true);
    }


    /**
     * Parses a JWE object from the specified string in json form. The
     * parsed JWE object will be given an {@link JWEObjectJSON.State#ENCRYPTED} state.
     *
     * NOTE: Supports only General Serialization Syntax
     *
     * @param s The string to parse. Must not be {@code null}.
     *
     * @return The JWE object.
     *
     * @throws ParseException If the string couldn't be parsed to a valid 
     *                        JWE object.
     */
    public static JWEObjectJSON parse(final String s)
            throws ParseException {
        Map<String, Object> json = JSONObjectUtils.parse(s);

        return new JWEObjectJSON(
                JSONObjectUtils.getBase64URL(json, "protected"),
                Recipient.parse(JSONObjectUtils.getJSONObjectArray(json, "recipients")),
                JSONObjectUtils.getBase64URL(json, "iv"),
                JSONObjectUtils.getBase64URL(json, "ciphertext"),
                JSONObjectUtils.getBase64URL(json, "tag"));
    }

    @Override
    public Map<String, Object> toJSONObject(boolean flattened) {
        // flattened JSON serialization is not implemented
        if (flattened) {
            throw new NotImplementedException();
        }

        List<Map<String, Object>> recipients = new ArrayList<>();

        for (Recipient recipient : getRecipients()) {
            recipients.add(recipient.toJSONObject());
        }

        byte[] header = JSONObjectUtils.toJSONString(getHeader().toJSONObject(), true)
                .getBytes(StandardCharsets.UTF_8);

        Map<String, Object> json = JSONObjectUtils.newJSONObject();
        json.put("iv", getIV().toString());
        json.put("recipients", recipients);
        json.put("tag", getAuthTag().toString());
        json.put("protected", Base64URL.encode(header).toString());
        json.put("ciphertext", getCipherText().toString());
        return json;
    }

    protected void setHeader(JWEHeader jweHeader) {
        if (jweHeader == null) {

            throw new IllegalArgumentException("The JWE header must not be null");
        }

        try {
            String json = JSONObjectUtils.toJSONString(jweHeader.toJSONObject(), true);
            Base64URL base64URL = Base64URL.encode(json.getBytes(StandardCharsets.UTF_8));
            this.header = JWEHeader.parse(base64URL);
        } catch (ParseException e) {

            throw new IllegalArgumentException("Invalid JWE header: " + e.getMessage());
        }
    }
}

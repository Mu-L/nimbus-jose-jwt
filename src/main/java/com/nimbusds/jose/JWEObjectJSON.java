package com.nimbusds.jose;

import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jose.util.JSONObjectUtils;

import java.text.ParseException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

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
     * The encrypted key, {@code null} if not computed or applicable.
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

        if (header == null) {

            throw new IllegalArgumentException("The JWE header must not be null");
        }

        this.header = header;

        if (payload == null) {

            throw new IllegalArgumentException("The payload must not be null");
        }

        setPayload(payload);

        recipients = null;

        cipherText = null;

        state = JWEObjectJSON.State.UNENCRYPTED;
    }

    public JWEObjectJSON(final Base64URL header,
                     final List<Recipient> recipients,
                     final Base64URL iv,
                     final Base64URL ciphertext,
                     final Base64URL tag)
            throws ParseException {

        if (header == null) {

            throw new IllegalArgumentException("The first part must not be null");
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

            throw new IllegalArgumentException("The fourth part must not be null");
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

        JWECryptoMultiParts parts;

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
     * Serialises this JWE object to its compact format consisting of 
     * Base64URL-encoded parts delimited by period ('.') characters. It 
     * must be in a {@link JWEObjectJSON.State#ENCRYPTED encrypted} or 
     * {@link JWEObjectJSON.State#DECRYPTED decrypted} state.
     *
     * <pre>
     * [header-base64url].[encryptedKey-base64url].[iv-base64url].[cipherText-base64url].[authTag-base64url]
     * </pre>
     *
     * @return The serialised JWE object.
     *
     * @throws IllegalStateException If the JWE object is not in a 
     *                               {@link JWEObjectJSON.State#ENCRYPTED encrypted} or
     *                               {@link JWEObjectJSON.State#DECRYPTED decrypted 
     *                               state}.
     */
    @Override
    public String serialize() {

        ensureEncryptedOrDecryptedState();

        return JSONObjectUtils.toJSONString(toJSONObject(false));
    }


    /**
     * Parses a JWE object from the specified string in compact form. The 
     * parsed JWE object will be given an {@link JWEObjectJSON.State#ENCRYPTED} state.
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

        List<Recipient> recipients = new ArrayList<>();
        Map<String, Object> json = JSONObjectUtils.parse(s);

        List<Object> recipientsJSON = JSONObjectUtils.getJSONArray(json, "recipients");
        if (recipientsJSON != null) {

            try {
                for (Map<String, Object> recipient : recipientsJSON.toArray(new HashMap[0])) {
                    recipients.add(Recipient.parse(recipient));
                }
            } catch (ArrayStoreException e) {

                throw new ParseException("JSON object member with key recipients is not an array of strings", 0);
            }

        }


        return new JWEObjectJSON(
                JSONObjectUtils.getBase64URL(json, "protected"),
                recipients,
                JSONObjectUtils.getBase64URL(json, "iv"),
                JSONObjectUtils.getBase64URL(json, "ciphertext"),
                JSONObjectUtils.getBase64URL(json, "tag"));
    }

    @Override
    public Map<String, Object> toJSONObject(boolean flattened) {
        List<Map<String, Object>> recipients = new ArrayList<>();

        for (Recipient recipient : getRecipients()) {
            recipients.add(recipient.toJSONObject());
        }

        Map<String, Object> json = new HashMap<>();
        json.put("iv", getIV().toString());
        json.put("recipients", recipients);
        json.put("tag", getAuthTag().toString());
        json.put("protected", getHeader().toBase64URL().toString());
        json.put("ciphertext", getCipherText().toString());
        return json;
    }
}

package com.nimbusds.jose.crypto.impl;

import com.nimbusds.jose.*;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.util.Base64URL;

import javax.crypto.SecretKey;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public class MultiCryptoProvider {
    public static <Key extends JWK> JWECryptoMultiParts encrypt(JWEHeader header, Key[] keys, byte[] clearText, final JWEEncryptorMulti<Key> encryptor) throws JOSEException {
        SecretKey cek = ContentCryptoProvider.generateCEK(header.getEncryptionMethod(), encryptor.getJCAContext().getSecureRandom());
        List<Recipient> recipients = new ArrayList<>();
        boolean encrypted = false;
        JWECryptoParts parts = null;

        for (Key key : keys) {
            Base64URL encryptedKey;

            if (!encrypted) {
                parts = encryptor.encrypt(header, key, cek, clearText);
                encryptedKey = parts.getEncryptedKey();
                encrypted = true;
            } else {
                encryptedKey = encryptor.deriveEncryptedKey(header, parts, key, cek);
            }

            if (encryptedKey != null) {
                Recipient recipient = new Recipient
                        .Builder()
                        .encryptedKey(encryptedKey)
                        .kid(key.getKeyID())
                        .build();

                recipients.add(recipient);
            }
        }

        return new JWECryptoMultiParts(
                parts.getHeader(),
                Collections.unmodifiableList(recipients),
                parts.getInitializationVector(),
                parts.getCipherText(),
                parts.getAuthenticationTag()
        );
    }

    public static <Key extends JWK> byte[] decrypt(
        final JWEHeader header,
        final Key[] keys,
        final List<Recipient> recipients,
        final Base64URL iv,
        final Base64URL cipherText,
        final Base64URL authTag,
        final JWEDecrypterMulti<Key> decryptor
    ) throws JOSEException {

        byte[] result = null;

        for (Key recipientKey : keys) {
            Recipient recipient = null;

            String kid = recipientKey.getKeyID();
            if (kid == null)
                throw new JOSEException("kid should be");

            for (Recipient rec : recipients) {
                if (kid.equals(rec.getHeader().get("kid"))) {
                    recipient = rec;
                }
            }

            if (recipient == null)
                throw new JOSEException("recipient not found");

            result = decryptor.decrypt(header, recipientKey, recipient, iv, cipherText, authTag);
        }

        return result;
    }

}

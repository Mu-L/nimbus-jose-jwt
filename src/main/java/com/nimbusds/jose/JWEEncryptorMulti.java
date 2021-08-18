package com.nimbusds.jose;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.util.Base64URL;

import javax.crypto.SecretKey;

public interface JWEEncryptorMulti<Key extends JWK> extends JWEProvider {
    JWECryptoMultiParts encrypt(final JWEHeader header, final byte[] clearText)
            throws JOSEException;

    JWECryptoParts encrypt(final JWEHeader header, Key key, SecretKey cek, final byte[] clearText)
            throws JOSEException;

    Base64URL deriveEncryptedKey(final JWEHeader header, JWECryptoParts parts,  Key key, SecretKey cek)
            throws JOSEException;
}

package com.nimbusds.jose;

import com.nimbusds.jose.crypto.*;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.OctetKeyPair;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jose.jwk.gen.OctetKeyPairGenerator;
import com.nimbusds.jose.util.Base64URL;
import junit.framework.TestCase;

public class JWEObjectJSONTest extends TestCase {

    private static ECKey generateECJWK(final Curve curve, String kid)
            throws Exception {
        return new ECKeyGenerator(curve).keyID(kid).generate();
    }

    private static OctetKeyPair generateOckeJWK(final Curve curve, String kid)
            throws Exception {
        return new OctetKeyPairGenerator(curve).keyID(kid).generate();
    }

    public void testECDH_1PU_multi_encrypt_decrypt() throws Exception {
        JWEHeader header = new JWEHeader.Builder(JWEAlgorithm.ECDH_1PU_A256KW, EncryptionMethod.A256CBC_HS512)
                .agreementPartyVInfo(Base64URL.encode("Alice"))
                .agreementPartyUInfo(Base64URL.encode("Bob"))
                .build();

        ECKey aliceKey = generateECJWK(Curve.P_521, "alice");
        ECKey bobKey = generateECJWK(Curve.P_521, "bob");
        ECKey charlieKey = generateECJWK(Curve.P_521, "charlie");

        JWEObjectJSON jwe = new JWEObjectJSON(header, new Payload("Hello, world"));
        ECDH1PUEncrypterMulti encrypterMulti = new ECDH1PUEncrypterMulti(aliceKey, new ECKey[]{ bobKey, charlieKey });
        jwe.encrypt(encrypterMulti);

        String json = jwe.serialize();

        JWEObjectJSON decrypted = JWEObjectJSON.parse(json);
        ECDH1PUDecrypterMulti decryptor = new ECDH1PUDecrypterMulti(aliceKey, new ECKey[]{ bobKey, charlieKey });
        decrypted.decrypt(decryptor);

        assertEquals("Hello, world", decrypted.getPayload().toString());
    }

    public void testECDH_ES_multi_encrypt_decrypt() throws Exception {
        JWEHeader header = new JWEHeader.Builder(JWEAlgorithm.ECDH_ES_A256KW, EncryptionMethod.A256CBC_HS512)
                .agreementPartyVInfo(Base64URL.encode("Alice"))
                .agreementPartyUInfo(Base64URL.encode("Bob"))
                .build();

        ECKey bobKey = generateECJWK(Curve.P_521, "bob");
        ECKey charlieKey = generateECJWK(Curve.P_521, "charlie");

        JWEObjectJSON jwe = new JWEObjectJSON(header, new Payload("Hello, world"));
        ECDHEncrypterMulti encrypterMulti = new ECDHEncrypterMulti(new ECKey[]{ bobKey, charlieKey });
        jwe.encrypt(encrypterMulti);

        String json = jwe.serialize();

        JWEObjectJSON decrypted = JWEObjectJSON.parse(json);
        ECDHDecrypterMulti decryptor = new ECDHDecrypterMulti(new ECKey[]{ bobKey, charlieKey });
        decrypted.decrypt(decryptor);

        assertEquals("Hello, world", decrypted.getPayload().toString());
    }

    public void testECDH_1PU_X25519_multi_encrypt_decrypt() throws Exception {
        JWEHeader header = new JWEHeader.Builder(JWEAlgorithm.ECDH_1PU_A256KW, EncryptionMethod.A256CBC_HS512)
                .agreementPartyVInfo(Base64URL.encode("Alice"))
                .agreementPartyUInfo(Base64URL.encode("Bob"))
                .build();

        OctetKeyPair aliceKey = generateOckeJWK(Curve.X25519, "alice");
        OctetKeyPair bobKey = generateOckeJWK(Curve.X25519, "bob");
        OctetKeyPair charlieKey = generateOckeJWK(Curve.X25519, "charlie");

        JWEObjectJSON jwe = new JWEObjectJSON(header, new Payload("Hello, world"));
        ECDH1PUX25519EncrypterMulti encrypterMulti = new ECDH1PUX25519EncrypterMulti(aliceKey, new OctetKeyPair[]{ bobKey, charlieKey });
        jwe.encrypt(encrypterMulti);

        String json = jwe.serialize();

        JWEObjectJSON decrypted = JWEObjectJSON.parse(json);
        ECDH1PUX25519DecrypterMulti decryptor = new ECDH1PUX25519DecrypterMulti(aliceKey, new OctetKeyPair[]{ bobKey, charlieKey });
        decrypted.decrypt(decryptor);

        assertEquals("Hello, world", decrypted.getPayload().toString());
    }

    public void testECDH_X25519_multi_encrypt_decrypt() throws Exception {
        JWEHeader header = new JWEHeader.Builder(JWEAlgorithm.ECDH_ES_A256KW, EncryptionMethod.A256CBC_HS512)
                .agreementPartyVInfo(Base64URL.encode("Alice"))
                .agreementPartyUInfo(Base64URL.encode("Bob"))
                .build();

        OctetKeyPair aliceKey = generateOckeJWK(Curve.X25519, "alice");
        OctetKeyPair bobKey = generateOckeJWK(Curve.X25519, "bob");
        OctetKeyPair charlieKey = generateOckeJWK(Curve.X25519, "charlie");

        JWEObjectJSON jwe = new JWEObjectJSON(header, new Payload("Hello, world"));
        X25519EncrypterMulti encrypterMulti = new X25519EncrypterMulti(new OctetKeyPair[]{ aliceKey, bobKey, charlieKey });
        jwe.encrypt(encrypterMulti);

        String json = jwe.serialize();

        JWEObjectJSON decrypted = JWEObjectJSON.parse(json);
        X25519DecrypterMulti decryptor = new X25519DecrypterMulti(new OctetKeyPair[]{ aliceKey, bobKey, charlieKey });
        decrypted.decrypt(decryptor);

        assertEquals("Hello, world", decrypted.getPayload().toString());
    }
}
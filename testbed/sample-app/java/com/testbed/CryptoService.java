package com.testbed;

import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.net.ssl.SSLContext;

/** Testbed Java service — deliberately mixed legacy and modern crypto. */
public class CryptoService {

    // BAD: MD5 digest
    public byte[] fingerprint(byte[] data) throws Exception {
        MessageDigest md = MessageDigest.getInstance("MD5");
        return md.digest(data);
    }

    // BAD: SHA-1
    public byte[] legacyHash(byte[] data) throws Exception {
        return MessageDigest.getInstance("SHA-1").digest(data);
    }

    // OK: SHA-256
    public byte[] strongHash(byte[] data) throws Exception {
        return MessageDigest.getInstance("SHA-256").digest(data);
    }

    // BAD: DES in ECB
    public Cipher legacyCipher() throws Exception {
        return Cipher.getInstance("DES/ECB/PKCS5Padding");
    }

    // BAD: AES-128 via transformation string
    public Cipher weakAes() throws Exception {
        return Cipher.getInstance("AES/CBC/PKCS5Padding");
    }

    // OK: AES-256 keygen
    public KeyGenerator aesKeygen() throws Exception {
        KeyGenerator kg = KeyGenerator.getInstance("AES");
        kg.init(256);
        return kg;
    }

    // BAD: RSA-2048 keypair (quantum-broken)
    public KeyPairGenerator rsaKeypair() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        return kpg;
    }

    // BAD: EC keypair (quantum-broken)
    public KeyPairGenerator ecKeypair() throws Exception {
        return KeyPairGenerator.getInstance("EC");
    }

    // BAD: forcing TLSv1
    public SSLContext legacyTls() throws Exception {
        return SSLContext.getInstance("TLSv1");
    }

    // OK: TLS 1.3
    public SSLContext modernTls() throws Exception {
        return SSLContext.getInstance("TLSv1.3");
    }
}

package com.forticode.cipherise;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;
import org.bouncycastle.util.io.pem.PemWriter;

import java.io.StringReader;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

class CryptoUtil {
    /**
     * Converts the given byte array to a hex string.
     *
     * @param data The byte array to convert.
     * @return A hex string consisting of the byte array.
     */
    static String toHexString(byte[] data) {
        return new String(Hex.encode(data), StandardCharsets.UTF_8);
    }

    /**
     * Converts the given hex string to a byte array.
     *
     * @param data The string to convert.
     * @return A byte array consisting of the string.
     */
    static byte[] fromHexString(String data) {
        return Hex.decode(data);
    }

    /**
     * Converts the given byte array to a Base64 string.
     *
     * @param data The byte array to convert.
     * @return A Base64 string consisting of the byte array.
     */
    static String toBase64String(byte[] data) {
        return new String(Base64.encode(data), StandardCharsets.UTF_8);
    }

    /**
     * Generate a RSA key pair of the given size.
     *
     * @return A RSA key pair of the given size.
     */
    static KeyPair generateRSAKeyPair(int keySize) throws CipheriseException {
        KeyPairGenerator generator;
        try {
            generator = KeyPairGenerator.getInstance("RSA");
        } catch (NoSuchAlgorithmException e) {
            throw new CipheriseException(e);
        }
        generator.initialize(keySize);
        return generator.generateKeyPair();
    }

    /**
     * Get the PKCS8 string for a Java PublicKey.
     *
     * @param publicKey The PublicKey to convert to string.
     * @return A PKCS8 string representing the
     * @throws CipheriseException
     */
    static String getPKCS8FromPublicKey(PublicKey publicKey) throws CipheriseException {
        try {
            StringWriter writer = new StringWriter();
            PemWriter pemWriter = new PemWriter(writer);
            pemWriter.writeObject(new PemObject("PUBLIC KEY", publicKey.getEncoded()));
            pemWriter.flush();
            pemWriter.close();

            return writer.toString();
        } catch (Exception e) {
            throw new CipheriseException(e);
        }
    }

    /**
     * Converts a PKCS8 public key string to a {@link PublicKey}.
     *
     * @param publicKeyString A PKCS8-encoded PEM public key string
     * @return A {@link PublicKey} if valid, or null otherwise.
     * @throws CipheriseException
     */
    static PublicKey getPublicKeyFromPKCS8(String publicKeyString) throws CipheriseException {
        try {
            PemReader pemReader = new PemReader(new StringReader(publicKeyString));
            X509EncodedKeySpec spec = new X509EncodedKeySpec(pemReader.readPemObject().getContent());
            KeyFactory kf = KeyFactory.getInstance("RSA");
            return kf.generatePublic(spec);
        } catch (Exception e) {
            throw new CipheriseException(e);
        }
    }

    /**
     * Get the PKCS8 string for a Java PrivateKey.
     *
     * @param privateKey The PrivateKey to convert to string.
     * @return A PKCS8 string representing the
     * @throws CipheriseException
     */
    static String getPKCS8FromPrivateKey(PrivateKey privateKey) throws CipheriseException {
        try {
            StringWriter writer = new StringWriter();
            PemWriter pemWriter = new PemWriter(writer);
            pemWriter.writeObject(new PemObject("PRIVATE KEY", privateKey.getEncoded()));
            pemWriter.flush();
            pemWriter.close();

            return writer.toString();
        } catch (Exception e) {
            throw new CipheriseException(e);
        }
    }

    /**
     * Converts a PKCS8 private key string to a {@link PrivateKey}.
     *
     * @param privateKeyString A PKCS8-encoded PEM private key string
     * @return A {@link PrivateKey} if valid, or null otherwise.
     * @throws CipheriseException
     */
    static PrivateKey getPrivateKeyFromPKCS8(String privateKeyString) throws CipheriseException {
        try (PemReader pemReader = new PemReader(new StringReader(privateKeyString))) {
            PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(pemReader.readPemObject().getContent());
            KeyFactory kf = KeyFactory.getInstance("RSA");
            return kf.generatePrivate(spec);
        } catch (Exception e) {
            throw new CipheriseException(e);
        }
    }

    /**
     * Get the PKCS1 DER for a Java PrivateKey.
     *
     * @param privateKey The PrivateKey to convert
     */
    static byte[] getPKCS1FromPrivateKey(PrivateKey privateKey) throws CipheriseException {
        try {
            byte[] privBytes = privateKey.getEncoded();
            PrivateKeyInfo pkInfo = PrivateKeyInfo.getInstance(privBytes);
            ASN1Encodable encodable = pkInfo.parsePrivateKey();
            ASN1Primitive primitive = encodable.toASN1Primitive();
            return primitive.getEncoded();
        } catch (Exception e) {
            throw new CipheriseException(e);
        }
    }

    /**
     * Converts PKCS1 private key DER to a {@link PrivateKey}.
     *
     * @param privateKeyString A PKCS1-encoded PEM private key
     */
    static PrivateKey getPrivateKeyFromPKCS1(byte[] data) throws CipheriseException {
        try {
            ASN1Primitive primitive = ASN1Primitive.fromByteArray(data);
            PrivateKeyInfo pkInfo = new PrivateKeyInfo(new AlgorithmIdentifier(PKCSObjectIdentifiers.rsaEncryption),
                    primitive);
            byte[] pkcs8 = pkInfo.getEncoded();

            PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(pkcs8);
            KeyFactory kf = KeyFactory.getInstance("RSA");
            return kf.generatePrivate(spec);
        } catch (Exception e) {
            throw new CipheriseException(e);
        }
    }

    static byte[] generateRandomBytes(int length) {
        SecureRandom random = new SecureRandom();
        byte[] ret = new byte[length];
        random.nextBytes(ret);
        return ret;
    }

    static byte[] aes256CfbEncrypt(byte[] key, byte[] iv, byte[] data) throws CipheriseException {
        try {
            SecretKeySpec aesSecret = new SecretKeySpec(key, "AES");
            Cipher cipher = Cipher.getInstance("AES/CFB/NoPadding");
            IvParameterSpec ivps = new IvParameterSpec(iv);
            cipher.init(Cipher.ENCRYPT_MODE, aesSecret, ivps);
            return cipher.doFinal(data);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException
                | InvalidAlgorithmParameterException | IllegalBlockSizeException | BadPaddingException e) {
            throw new CipheriseException(e);
        }
    }

    static byte[] aes256CfbDecrypt(byte[] key, byte[] iv, byte[] data) throws CipheriseException {
        try {
            SecretKeySpec aesSecret = new SecretKeySpec(key, "AES");
            Cipher cipher = Cipher.getInstance("AES/CFB/NoPadding");
            IvParameterSpec ivps = new IvParameterSpec(iv);
            cipher.init(Cipher.DECRYPT_MODE, aesSecret, ivps);
            return cipher.doFinal(data);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException
                | InvalidAlgorithmParameterException | IllegalBlockSizeException | BadPaddingException e) {
            throw new CipheriseException(e);
        }
    }

    static byte[] rsaEncrypt(PublicKey key, byte[] data) throws CipheriseException {
        try {
            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(Cipher.ENCRYPT_MODE, key);
            return cipher.doFinal(data);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException
                | BadPaddingException e) {
            throw new CipheriseException(e);
        }
    }

    static byte[] rsaDecrypt(PrivateKey key, byte[] data) throws CipheriseException {
        try {
            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(Cipher.DECRYPT_MODE, key);
            return cipher.doFinal(data);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException
                | BadPaddingException e) {
            throw new CipheriseException(e);
        }
    }
}

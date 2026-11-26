package io.javacryptokit.cli;

import io.javacryptokit.CredentialCrypto;
import io.javacryptokit.i18n.Messages;
import io.javacryptokit.security.*;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.time.Instant;
import java.util.Arrays;

import static io.javacryptokit.cli.ApiInput.problem;

/** Encryption, signature, certificate and test-key commands. */
final class ApiCrypto {
    private ApiCrypto() { }

    static int run(String family, String action, ApiInput a) throws Exception {
        switch (family) {
            case "aes": return aes(action, a);
            case "rsa": case "hybrid": return publicKeyCipher(family, action, a);
            case "signature": return signature(action, a);
            case "certificate": return certificate(a);
            case "keygen": return keygen(a);
            case "keyconvert": return convert(a);
            default: throw new IllegalStateException("api command");
        }
    }

    static Pbkdf2Algorithm pbkdf2(ApiInput a, String option) throws CryptoCli.CliException {
        String id = a.choice(option, "sha256", "sha256", "sha512", "pbkdf2-sha256", "pbkdf2-sha512");
        return id.endsWith("512") ? Pbkdf2Algorithm.SHA512 : Pbkdf2Algorithm.SHA256;
    }

    static HmacAlgorithm hmac(ApiInput a) throws CryptoCli.CliException {
        return "sha512".equals(a.choice("algorithm", "sha256", "sha256", "sha512"))
                ? HmacAlgorithm.SHA512 : HmacAlgorithm.SHA256;
    }

    static PublicKey publicKey(ApiInput a) throws Exception {
        return readPublicKey(a, "public-key");
    }

    static PrivateKey privateKey(ApiInput a) throws Exception {
        return readPrivateKey(a, "private-key");
    }

    private static PublicKey readPublicKey(ApiInput a, String option) throws CryptoCli.CliException {
        Path input = a.path(option);
        try {
            return PemKeys.readPublicKeyFile(input);
        } catch (java.io.IOException e) {
            throw new CryptoCli.CliException("IO_ERROR", Messages.get("api.err.read", "--" + option));
        } catch (IllegalArgumentException e) {
            throw ApiInput.invalid("api.err.publicKey", "--" + option);
        }
    }

    private static PrivateKey readPrivateKey(ApiInput a, String option) throws CryptoCli.CliException {
        Path input = a.protectedPath(option);
        try {
            return PemKeys.readPrivateKeyFile(input);
        } catch (java.io.IOException e) {
            throw new CryptoCli.CliException("IO_ERROR", Messages.get("api.err.read", "--" + option));
        } catch (IllegalArgumentException e) {
            throw ApiInput.invalid("api.err.privateKey", "--" + option);
        }
    }

    private static int aes(String action, ApiInput a) throws Exception {
        boolean decrypt = action.equals("decrypt");
        Path out = a.target(decrypt);
        String type = a.choice("type", "key", "key", "pass");
        AesKeySize size = "aes-128-gcm".equals(a.choice("algorithm", "aes-256-gcm", "aes-128-gcm", "aes-256-gcm"))
                ? AesKeySize.AES_128 : AesKeySize.AES_256;
        boolean enc = "enc".equals(a.choice("format", "raw", "raw", "enc"));
        String id = enc ? a.ask("key-id") : null;
        if (enc) {
            a.excludes("aad", "aad-file", "encoding", "input-encoding");
            if (size != AesKeySize.AES_256) throw problem("api.err.incompatible", "--algorithm");
        } else {
            a.excludes("key-id");
        }
        if (type.equals("key")) a.excludes("kdf", "salt", "salt-file", "iterations", "pass-file");
        else a.excludes("key-file", "key-encoding");
        byte[] aad = a.associated("aad", HybridEncryption.MAX_AAD_BYTES);
        byte[] key = null;
        char[] phrase = null;
        byte[] salt = null;
        Pbkdf2Algorithm kdf = null;
        int iterations = 0;
        if ("pass".equals(type)) {
            kdf = pbkdf2(a, "kdf");
            salt = enc ? a.salt(Pbkdf2.SALT_BYTES, Pbkdf2.SALT_BYTES)
                    : a.salt(Pbkdf2.MIN_SALT_BYTES, Pbkdf2.MAX_SALT_BYTES);
            iterations = a.integer("iterations", kdf.recommendedIterations(), Pbkdf2.MIN_ITERATIONS, Pbkdf2.MAX_ITERATIONS);
            phrase = a.password("pass-file");
        } else {
            key = a.key("key-file", "base64");
            if (key.length != size.keyBytes()) {
                throw ApiInput.invalid("api.err.aesKeyLength", size.keyBytes() * 8, size.keyBytes());
            }
        }
        if (id != null) {
            CredentialCrypto direct = phrase == null ? CredentialCrypto.fromRawKey(id, key) :
                    CredentialCrypto.fromPassphrase(id, phrase, salt, iterations, kdf);
            if (decrypt) a.binary(out, a.keep(direct.decryptBytes(a.text("in", 32 * 1024, false))), true);
            else a.result(out, direct.encryptBytes(a.data("in", 32 * 1024, true)), false);
            return 0;
        }
        AesGcm aes = phrase == null ? AesGcm.of(size, key) : AesGcm.fromPassphrase(size, kdf, phrase, salt, iterations);
        if (decrypt) {
            byte[] sealed = a.decoded("in", 2 * ApiInput.MIB + 128, false, a.encoding("input-encoding", "base64"));
            a.binary(out, a.keep(aes.decrypt(sealed, aad)), true);
        } else {
            byte[] plain = a.data("in", ApiInput.MIB, true);
            a.result(out, a.encoding("encoding", "base64").encode(aes.encrypt(plain, aad)), false);
        }
        return 0;
    }

    private static int publicKeyCipher(String family, String action, ApiInput a) throws Exception {
        boolean decrypt = action.equals("decrypt");
        boolean hybrid = family.equals("hybrid");
        Path out = a.target(decrypt);
        RsaOaepAlgorithm rsa = null;
        byte[] aad = null;
        if (hybrid) aad = a.associated("aad", HybridEncryption.MAX_AAD_BYTES);
        else rsa = "sha512".equals(a.choice("algorithm", "sha256", "sha256", "sha512"))
                ? RsaOaepAlgorithm.SHA512 : RsaOaepAlgorithm.SHA256;
        if (decrypt) {
            PrivateKey key = privateKey(a);
            if (!(key instanceof java.security.interfaces.RSAKey)) throw ApiInput.invalid("api.err.rsaKey", "--private-key");
            int limit = hybrid ? (2 * HybridEncryption.MAX_PLAINTEXT_BYTES + ApiInput.KEY_LIMIT) : ApiInput.KEY_LIMIT;
            byte[] sealed = a.decoded("in", limit, false, a.encoding("input-encoding", "base64"));
            byte[] plain = hybrid ? HybridEncryption.decrypt(key, sealed, aad) : RsaOaep.decrypt(key, sealed, rsa);
            a.binary(out, a.keep(plain), true);
        } else {
            PublicKey key = publicKey(a);
            byte[] plain;
            if (hybrid) {
                if (!(key instanceof java.security.interfaces.RSAKey)) throw ApiInput.invalid("api.err.rsaKey", "--public-key");
                plain = a.data("in", HybridEncryption.MAX_PLAINTEXT_BYTES, true);
            } else {
                if (!(key instanceof java.security.interfaces.RSAKey)) throw ApiInput.invalid("api.err.rsaKey", "--public-key");
                int limit = RsaOaep.maxPlaintextBytes(key, rsa);
                plain = a.data("in", limit, true, "api.err.rsaLength", limit);
            }
            byte[] sealed = hybrid ? HybridEncryption.encrypt(key, plain, aad) : RsaOaep.encrypt(key, plain, rsa);
            a.result(out, a.encoding("encoding", "base64").encode(sealed), false);
        }
        return 0;
    }

    private static int signature(String action, ApiInput a) throws Exception {
        SignatureAlgorithm alg = "rsa-sha256".equals(a.choice("algorithm", "rsa-sha256", "rsa-sha256", "ecdsa-sha256"))
                ? SignatureAlgorithm.RSA_SHA256 : SignatureAlgorithm.ECDSA_P256_SHA256;
        Encoding encoding = a.encoding("encoding", "base64");
        Path file = a.value("in") == null ? null : a.path("in");
        if (action.equals("sign")) {
            Path out = a.target(false);
            PrivateKey key = privateKey(a);
            byte[] signed = file == null ? Signatures.sign(alg, key, a.data("in", ApiInput.MIB, false))
                    : Signatures.signFile(alg, key, file);
            a.result(out, encoding.encode(signed), false);
            return 0;
        }
        PublicKey key = publicKey(a);
        byte[] signature = a.decoded("signature-file", ApiInput.KEY_LIMIT, false, encoding);
        return a.verify(file == null ? Signatures.verify(alg, key, a.data("in", ApiInput.MIB, false), signature)
                : Signatures.verifyFile(alg, key, file, signature));
    }

    private static int certificate(ApiInput a) throws Exception {
        Path out = a.target(false);
        Instant now = a.instant("at", Instant.now());
        CertificateInfo info = Certificates.info(Certificates.readFile(a.path("in")));
        a.result(out, Messages.get("api.cert", Messages.singleLine(info.subject()), Messages.singleLine(info.issuer()), info.serialNumberHex(),
                info.notBefore(), info.notAfter(), info.isValidAt(now), info.daysUntilExpiry(now),
                info.publicKeyAlgorithm(), info.publicKeySize(), info.signatureAlgorithm(),
                info.sha256Fingerprint(), Messages.singleLine(info.subjectAlternativeNames().toString())), false);
        return 0;
    }

    private static int keygen(ApiInput a) throws Exception {
        String kind = a.choice("type", null, "aes", "hmac", "rsa", "ec", "otp");
        if (kind.equals("otp")) a.choice("encoding", "base32", "base32");
        Path out = a.target(true);
        String reason = a.ask("reason");
        JarConfigEditor.checkReason(reason);
        if (kind.equals("rsa") || kind.equals("ec")) {
            a.excludes("algorithm", "encoding", "show");
            if (out == null) throw problem("api.err.required", "--out");
            Path publicOut = ApiInput.newTarget(Paths.get(out + "-public.pem"));
            Path privateOut = ApiInput.newTarget(Paths.get(out + "-private.pem"));
            KeyPair pair;
            if (kind.equals("rsa")) {
                pair = Signatures.generateRsaKeyPair(Integer.parseInt(a.choice("bits", "3072", "2048", "3072", "4096")));
            } else {
                a.excludes("bits");
                pair = Signatures.generateKeyPair(SignatureAlgorithm.ECDSA_P256_SHA256);
            }
            a.publish(publicOut, Bytes.utf8(PemKeys.toPem(pair.getPublic())));
            byte[] secret = Bytes.utf8(PemKeys.toPem(pair.getPrivate()));
            try {
                a.publish(privateOut, secret);
            } catch (Exception e) {
                a.err.println(Messages.get("api.keypair.partial", io.javacryptokit.key.SecretFiles.fileName(publicOut)));
                throw e;
            } finally {
                Arrays.fill(secret, (byte) 0);
            }
            return 0;
        }
        Encoding outputEncoding = a.encoding("encoding", kind.equals("otp") ? "base32" : "base64");
        byte[] key;
        switch (kind) {
            case "aes":
                a.excludes("algorithm");
                String bits = a.choice("bits", "256", "128", "256");
                key = AesGcm.generateKey(bits.equals("128") ? AesKeySize.AES_128 : AesKeySize.AES_256);
                break;
            case "hmac":
                a.excludes("bits");
                key = Hmac.generateKey(hmac(a));
                break;
            default:
                a.excludes("bits");
                key = Totp.generateSecret(OtpAlgorithm.valueOf(a.choice("algorithm", "sha1", "sha1", "sha256", "sha512")
                        .toUpperCase(java.util.Locale.ROOT)));
        }
        a.result(out, outputEncoding.encode(a.keep(key)), true);
        return 0;
    }

    private static int convert(ApiInput a) throws Exception {
        Path out = ApiInput.newTarget(a.path("out"));
        boolean secret = a.choice("type", null, "public", "private").equals("private");
        String format = a.choice("format", null, "pem", "der");
        if (secret) {
            PrivateKey key = readPrivateKey(a, "in");
            a.publish(out, a.keep(format.equals("pem") ? Bytes.utf8(PemKeys.toPem(key)) : PemKeys.toDer(key)));
        } else {
            PublicKey key = readPublicKey(a, "in");
            a.publish(out, format.equals("pem") ? Bytes.utf8(PemKeys.toPem(key)) : PemKeys.toDer(key));
        }
        return 0;
    }
}

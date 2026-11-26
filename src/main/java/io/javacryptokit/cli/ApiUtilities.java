package io.javacryptokit.cli;

import io.javacryptokit.security.*;
import java.nio.file.Path;
import java.util.Locale;

/** Stateless data utilities backed by the public API. */
final class ApiUtilities {
    private ApiUtilities() { }

    static int run(String family, String action, ApiInput a) throws Exception {
        switch (family) {
            case "hmac": return hmac(action, a);
            case "hash": return hash(action, a);
            case "encode": case "decode": return codec(family, a);
            case "random": return random(action, a);
            case "password": return password(action, a);
            case "kdf": return kdf(action, a);
            default: throw new IllegalStateException("api command");
        }
    }

    private static int hmac(String action, ApiInput a) throws Exception {
        Path out = a.target(false);
        HmacAlgorithm algorithm = ApiCrypto.hmac(a);
        byte[] key = a.key("key-file", "base64");
        Hmac hmac = a.flag("external-key") ? Hmac.ofExternalKey(algorithm, key) : Hmac.of(algorithm, key);
        Encoding enc = a.encoding("encoding", "hex");
        byte[] data = a.data("in", ApiInput.MIB, true);
        if (action.equals("verify")) {
            return a.verify(hmac.verify(data, a.text("expected-file", ApiInput.KEY_LIMIT, false), enc));
        }
        a.result(out, hmac.sign(data, enc), false);
        return 0;
    }

    private static int hash(String action, ApiInput a) throws Exception {
        Path out = a.target(false);
        DigestAlgorithm alg = "sha512".equals(a.choice("algorithm", "sha256", "sha256", "sha512"))
                ? DigestAlgorithm.SHA512 : DigestAlgorithm.SHA256;
        Encoding encoding = a.encoding("encoding", "hex");
        Path file = a.value("in") == null ? null : a.path("in");
        if (action.equals("verify")) {
            String expected = a.text("expected-file", ApiInput.KEY_LIMIT, false);
            return a.verify(file == null ? Bytes.equalsConstantTime(encoding.decode(expected),
                    Digests.hash(alg, a.data("in", ApiInput.MIB, false)))
                    : Digests.verifyFile(alg, file, expected, encoding));
        }
        byte[] digest = file == null ? Digests.hash(alg, a.data("in", ApiInput.MIB, false)) : Digests.hashFile(alg, file);
        a.result(out, encoding.encode(digest), false);
        return 0;
    }

    private static int codec(String command, ApiInput a) throws Exception {
        Path out = a.target(false);
        Encoding format = a.encoding("encoding", "base64");
        if (command.equals("encode")) a.result(out, format.encode(a.data("in", ApiInput.MIB, false)), false);
        else {
            // Hex needs two characters per byte. Leave room for a UTF-8 BOM and CRLF.
            a.binary(out, a.decoded("in", 2 * ApiInput.MIB + 5, false, format), false);
        }
        return 0;
    }

    private static int random(String action, ApiInput a) throws Exception {
        boolean secret = !(action.equals("uuid") || action.equals("nonce"));
        Path out = a.target(secret);
        String value;
        switch (action) {
            case "uuid": value = SecureRandoms.uuidV4().toString(); break;
            case "nonce": value = SecureRandoms.nonce(); break;
            case "string":
                String alphabet = a.choice("alphabet", "alphanumeric", "digits", "upper", "lower", "letters",
                        "upper-digits", "lower-digits", "alphanumeric");
                value = SecureRandoms.string(a.integer("length", 32, 1, 1024),
                        SecureRandoms.Alphabet.valueOf(alphabet.toUpperCase(Locale.ROOT).replace('-', '_')), a.value("prefix", ""));
                break;
            case "bytes":
                value = a.encoding("encoding", "base64").encode(a.keep(SecureRandoms.bytes(
                        a.integer("length", 32, 1, SecureRandoms.MAX_BYTES))));
                break;
            case "token":
                value = SecureRandoms.token(a.integer("length", SecureRandoms.DEFAULT_TOKEN_BYTES, SecureRandoms.MIN_TOKEN_BYTES,
                        SecureRandoms.MAX_TOKEN_BYTES), a.encoding("encoding", "base64url"));
                break;
            default: throw new IllegalStateException("random command");
        }
        a.result(out, value, secret);
        return 0;
    }

    private static int password(String action, ApiInput a) throws Exception {
        if (action.equals("verify")) {
            String stored = a.text("in", ApiInput.KEY_LIMIT, true);
            return a.verify(Passwords.verify(a.password("password-file"), stored));
        }
        Pbkdf2Algorithm alg = ApiCrypto.pbkdf2(a, "algorithm");
        int iterations = a.integer("iterations", alg.recommendedIterations(), Pbkdf2.MIN_ITERATIONS, Pbkdf2.MAX_ITERATIONS);
        if (action.equals("needs-rehash")) {
            a.out.println(Passwords.needsRehash(a.text("in", ApiInput.KEY_LIMIT, true), alg, iterations));
        } else {
            Path out = a.target(true);
            a.result(out, Passwords.hash(a.password("password-file"), alg, iterations), true);
        }
        return 0;
    }

    private static int kdf(String action, ApiInput a) throws Exception {
        Path out = a.target(true);
        Encoding format = a.encoding("encoding", "base64");
        byte[] key;
        if (action.equals("pbkdf2")) {
            Pbkdf2Algorithm alg = ApiCrypto.pbkdf2(a, "algorithm");
            byte[] salt = a.salt(Pbkdf2.MIN_SALT_BYTES, Pbkdf2.MAX_SALT_BYTES);
            int iterations = a.integer("iterations", alg.recommendedIterations(), Pbkdf2.MIN_ITERATIONS, Pbkdf2.MAX_ITERATIONS);
            int length = a.integer("length", 32, 16, 64);
            key = Pbkdf2.deriveKey(alg, a.password("pass-file"), salt, iterations, length);
        } else {
            HmacAlgorithm alg = ApiCrypto.hmac(a);
            byte[] salt = a.salt();
            byte[] info = a.associated("info", ApiInput.KEY_LIMIT);
            int length = a.integer("length", 32, 1, 255 * alg.length());
            key = Hkdf.derive(alg, a.key("key-file", "base64"), salt, info, length);
        }
        a.result(out, format.encode(a.keep(key)), true);
        return 0;
    }
}

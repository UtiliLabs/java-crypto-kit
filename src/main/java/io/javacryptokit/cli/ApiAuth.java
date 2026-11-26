package io.javacryptokit.cli;

import io.javacryptokit.i18n.Messages;
import io.javacryptokit.json.StrictJson;
import io.javacryptokit.jwt.*;
import io.javacryptokit.security.*;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import static io.javacryptokit.cli.ApiInput.problem;

/** Token, OTP and request-authentication adapters. No token or counter state is retained. */
final class ApiAuth {
    static final int TOKEN_LIMIT = 64 * 1024;
    private static final List<String> REGISTERED = Arrays.asList("iss", "sub", "aud", "exp", "nbf", "iat", "jti");

    private ApiAuth() { }

    static int run(String family, String action, ApiInput a) throws Exception {
        switch (family) {
            case "jwt": return jwt(action, a);
            case "otp": return otp(action, a);
            case "oauth": return ApiOAuth.run(action, a);
            case "request-auth": return requestAuth(action, a);
            default: throw new IllegalStateException("api command");
        }
    }

    static JwtAlgorithm algorithm(ApiInput a) throws CryptoCli.CliException {
        switch (a.choice("algorithm", null, "hs256", "rs256", "es256")) {
            case "hs256": return JwtAlgorithm.HS256;
            case "rs256": return JwtAlgorithm.RS256;
            default: return JwtAlgorithm.ES256;
        }
    }

    static JwtKey signingKey(ApiInput a, JwtAlgorithm algorithm) throws Exception {
        JwtKey key;
        if (algorithm == JwtAlgorithm.HS256) {
            a.excludes("private-key");
            byte[] bytes = a.key("key-file", "base64");
            if (bytes.length < 32) throw ApiInput.invalid("api.err.hs256Key");
            key = JwtKey.hs256(bytes);
        } else {
            a.excludes("key-file", "key-encoding");
            java.security.PrivateKey privateKey = ApiCrypto.privateKey(a);
            try {
                key = algorithm == JwtAlgorithm.RS256 ? JwtKey.rs256(privateKey) : JwtKey.es256(privateKey);
            } catch (IllegalArgumentException e) {
                throw ApiInput.invalid("api.err.joseKey", "--private-key", algorithm.name());
            }
        }
        return withKid(a, key);
    }

    static List<JwtKey> verificationKeys(ApiInput a, JwtAlgorithm algorithm) throws Exception {
        JwtKey key;
        if (a.value("jwks-file") != null) {
            if (algorithm == JwtAlgorithm.HS256) throw problem("api.err.incompatible", "--jwks-file");
            a.excludes("public-key", "key-file", "key-encoding");
            String jwks = a.text("jwks-file", ApiInput.MIB, false);
            List<JwtKey> trusted;
            try {
                trusted = a.value("issuer") == null ? Jwks.parse(jwks) : Jwks.parse(jwks, a.value("issuer"));
            } catch (IllegalArgumentException e) {
                throw ApiInput.invalid("api.err.jwksFormat");
            }
            List<JwtKey> matching = new ArrayList<>();
            for (JwtKey candidate : trusted) {
                if (candidate.algorithm() == algorithm && (a.value("kid") == null || a.value("kid").equals(candidate.keyId()))) {
                    matching.add(candidate);
                }
            }
            if (matching.isEmpty()) throw problem("api.err.jwks");
            return matching;
        }
        if (algorithm == JwtAlgorithm.HS256) {
            a.excludes("public-key");
            byte[] bytes = a.key("key-file", "base64");
            if (bytes.length < 32) throw ApiInput.invalid("api.err.hs256Key");
            key = JwtKey.hs256(bytes);
        } else {
            a.excludes("key-file", "key-encoding");
            java.security.PublicKey publicKey = ApiCrypto.publicKey(a);
            try {
                key = algorithm == JwtAlgorithm.RS256 ? JwtKey.rs256(publicKey) : JwtKey.es256(publicKey);
            } catch (IllegalArgumentException e) {
                throw ApiInput.invalid("api.err.joseKey", "--public-key", algorithm.name());
            }
        }
        return Collections.singletonList(withKid(a, key));
    }

    private static JwtKey withKid(ApiInput a, JwtKey key) throws CryptoCli.CliException {
        String id = a.value("kid");
        try {
            return id == null ? key : key.withKeyId(id);
        } catch (IllegalArgumentException e) {
            throw ApiInput.invalid("api.err.kid");
        }
    }

    static String[] words(String value) {
        return value.trim().split("\\s+");
    }

    static Clock clock(ApiInput a, String opt) throws CryptoCli.CliException {
        Instant specified = a.instant(opt, null);
        return specified == null ? Clock.systemUTC() : Clock.fixed(specified, ZoneOffset.UTC);
    }

    static Map<?, ?> claims(ApiInput a) throws Exception {
        if (a.value("claims-file") == null) return Collections.emptyMap();
        Object root = a.json("claims-file", TOKEN_LIMIT,
                StrictJson.Limits.of(16, 1000, 10000, TOKEN_LIMIT));
        if (!(root instanceof Map<?, ?>)) throw problem("api.err.claims");
        Map<?, ?> claims = (Map<?, ?>) root;
        for (Object name : claims.keySet()) if (REGISTERED.contains(name)) throw problem("api.err.claims");
        return claims;
    }

    static Map<String, String> expectedClaims(ApiInput a) throws Exception {
        Map<String, String> expected = new java.util.LinkedHashMap<>();
        if (a.value("require-claim-values-file") == null) return expected;
        Object raw = a.json("require-claim-values-file", TOKEN_LIMIT,
                StrictJson.Limits.of(4, 1000, 1000, TOKEN_LIMIT));
        if (!(raw instanceof Map<?, ?>)) throw problem("api.err.claimValues");
        for (Map.Entry<?, ?> entry : ((Map<?, ?>) raw).entrySet()) {
            if (!(entry.getValue() instanceof String)) throw problem("api.err.claimValues");
            expected.put((String) entry.getKey(), (String) entry.getValue());
        }
        return expected;
    }

    static void expected(Map<String, String> claims, String claim, String value) throws CryptoCli.CliException {
        if (claims.containsKey(claim)) throw problem("api.err.claimDuplicate");
        claims.put(claim, value);
    }

    private static int jwt(String action, ApiInput a) throws Exception {
        if (action.equals("inspect")) {
            Path out = a.target(true);
            UnverifiedJwt token = Jwt.parseUnverified(token(a));
            a.result(out, Messages.get("api.jwt.unverified") + "\n\n" + Messages.get("api.jwt.inspect",
                    token.header().toJson(), token.claims().toJson()), true);
            return 0;
        }
        JwtAlgorithm algorithm = algorithm(a);
        if (action.equals("create")) {
            Path out = a.target(true);
            Jwt.Builder builder = Jwt.builder().expiresIn(a.seconds("expires-in", 300, 1, Integer.MAX_VALUE));
            if (a.value("issuer") != null) builder.issuer(a.required("issuer"));
            if (a.value("subject") != null) builder.subject(a.required("subject"));
            if (a.value("audience") != null) builder.audience(words(a.required("audience")));
            if (a.value("jwt-id") != null) builder.jwtId(a.required("jwt-id"));
            if (a.value("issued-at") != null) builder.issuedAt(a.instant("issued-at", null));
            if (a.value("not-before") != null) builder.notBefore(a.instant("not-before", null));
            for (Map.Entry<?, ?> claim : claims(a).entrySet()) addJwtClaim(builder, (String) claim.getKey(), claim.getValue());
            a.result(out, builder.sign(signingKey(a, algorithm)), true);
            return 0;
        }
        String audience = null;
        if (a.flag("any-audience")) a.excludes("audience");
        else audience = a.ask("audience");
        JwtVerifier.Builder builder = JwtVerifier.builder().requireExpiration(true)
                .clock(clock(a, "at")).clockSkew(a.seconds("clock-skew", 0, 0, 300))
                .keys(verificationKeys(a, algorithm));
        if (a.value("issuer") != null) builder.issuer(a.required("issuer"));
        if (audience == null) builder.anyAudience();
        else builder.audience(audience);
        if (a.value("typ") != null) builder.types(words(a.required("typ")));
        if (a.value("require-claims") != null) builder.requireClaims(words(a.required("require-claims")));
        Map<String, String> expected = expectedClaims(a);
        if (a.value("subject") != null) expected(expected, "sub", a.required("subject"));
        expected.forEach(builder::requireClaimValue);
        JwtVerifier verifier = builder.build();
        String token = token(a);
        try {
            return verifyKid(a, verifier.verify(token).keyId());
        } catch (JwtException e) {
            return rejected(a, e.getReason());
        }
    }

    static String token(ApiInput a) throws CryptoCli.CliException {
        String token = a.text("in", TOKEN_LIMIT + 5, true, "api.err.jwtLimit");
        if (token.length() > TOKEN_LIMIT) throw problem("api.err.jwtLimit");
        return token;
    }

    static int verifyKid(ApiInput a, String trustedKid) {
        String expected = a.value("kid");
        return expected == null || expected.equals(trustedKid)
                ? a.verify(true) : rejected(a, JwtException.Reason.KEY_NOT_FOUND);
    }

    static int rejected(ApiInput a, JwtException.Reason reason) {
        a.err.println(Messages.error(reason.name(), Messages.get("api.err.jwt." + reason.name())));
        return a.verify(false);
    }

    @SuppressWarnings("unchecked")
    private static void addJwtClaim(Jwt.Builder builder, String name, Object value) throws CryptoCli.CliException {
        if (value instanceof String) builder.claim(name, (String) value);
        else if (value instanceof Long) builder.claim(name, (Long) value);
        else if (value instanceof Boolean) builder.claim(name, (Boolean) value);
        else if (value instanceof Map<?, ?>) builder.claim(name, (Map<String, ?>) value);
        else if (value instanceof List<?>) {
            List<String> list = new ArrayList<>();
            for (Object item : (List<?>) value) {
                if (!(item instanceof String)) throw problem("api.err.claims");
                list.add((String) item);
            }
            builder.claim(name, list);
        } else throw problem("api.err.claims");
    }

    private static int otp(String action, ApiInput a) throws Exception {
        boolean verify = action.equals("verify");
        String type = a.choice("type", "totp", "hotp", "totp");
        if (type.equals("hotp") && action.equals("uri")) throw problem("api.err.otpUri");
        Path out = verify ? null : a.target(true);
        int digits = a.integer("digits", 6, 6, 8);
        OtpAlgorithm alg = OtpAlgorithm.valueOf(a.choice("algorithm", "sha1", "sha1", "sha256", "sha512")
                .toUpperCase(java.util.Locale.ROOT));
        byte[] secret = a.keep(a.decoded("key-file", ApiInput.KEY_LIMIT, true, Encoding.BASE32));
        if (type.equals("hotp")) {
            a.excludes("period", "at");
            if (alg != OtpAlgorithm.SHA1) throw problem("api.err.incompatible", "--algorithm");
            long counter = a.number("counter", null, 0, Long.MAX_VALUE);
            Hotp hotp = Hotp.of(secret, digits);
            if (verify) return a.verify(hotp.verify(a.text("in", ApiInput.KEY_LIMIT, true), counter,
                    a.integer("window", 0, 0, Hotp.MAX_LOOK_AHEAD)).isPresent());
            a.result(out, hotp.generate(counter), true);
        } else {
            a.excludes("counter");
            Totp totp = Totp.of(secret, alg, digits, a.seconds("period", 30, 15, 300));
            if (action.equals("uri")) a.result(out, totp.otpauthUri(a.ask("issuer"), a.ask("account")), true);
            else {
                Instant at = a.instant("at", Instant.now());
                if (verify) return a.verify(totp.verify(a.text("in", ApiInput.KEY_LIMIT, true), at,
                        a.integer("window", 0, 0, Totp.MAX_WINDOW)).isPresent());
                a.result(out, totp.generate(at), true);
            }
        }
        return 0;
    }

    private static int requestAuth(String action, ApiInput a) throws Exception {
        HmacAlgorithm alg = ApiCrypto.hmac(a);
        Path out = a.target(false);
        Clock clock = a.value("at") == null ? Clock.systemUTC()
                : Clock.fixed(Instant.ofEpochSecond(a.number("at", null, 0, 999999999999L)), ZoneOffset.UTC);
        RequestAuth auth = RequestAuth.of(Hmac.of(alg, a.key("key-file", "base64")),
                a.seconds("clock-skew", 300, 1, 900), clock);
        byte[] data = a.data("in", ApiInput.MIB, true);
        if (action.equals("sign")) {
            RequestAuth.Signed signed = auth.sign(data);
            Map<String, String> metadata = new java.util.LinkedHashMap<>();
            metadata.put("timestamp", signed.timestamp());
            metadata.put("nonce", signed.nonce());
            metadata.put("mac", signed.mac());
            a.jsonResult(out, metadata, false);
            return 0;
        }
        String timestamp;
        String nonce;
        String mac;
        if (a.value("auth-file") != null) {
            a.excludes("timestamp", "nonce", "mac");
            Object root = a.json("auth-file", ApiInput.KEY_LIMIT, StrictJson.Limits.DEFAULT);
            if (!(root instanceof Map<?, ?>) || ((Map<?, ?>) root).size() != 3) throw ApiInput.invalid("api.err.authFile");
            Map<?, ?> metadata = (Map<?, ?>) root;
            timestamp = field(metadata, "timestamp");
            nonce = field(metadata, "nonce");
            mac = field(metadata, "mac");
        } else {
            timestamp = a.ask("timestamp");
            nonce = a.ask("nonce");
            mac = a.ask("mac");
        }
        RequestAuth.Result result = auth.verify(data, timestamp, nonce, mac);
        if (!result.isValid()) a.err.println(result.name());
        return a.verify(result.isValid());
    }

    private static String field(Map<?, ?> metadata, String name) throws CryptoCli.CliException {
        Object value = metadata.get(name);
        if (!(value instanceof String)) throw ApiInput.invalid("api.err.authFile");
        return (String) value;
    }
}

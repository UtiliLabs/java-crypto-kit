package io.javacryptokit.cli;

import io.javacryptokit.json.StrictJson;
import io.javacryptokit.i18n.Messages;
import io.javacryptokit.jwt.JwtAlgorithm;
import io.javacryptokit.jwt.JwtKey;
import io.javacryptokit.oauth.AccessTokenVerifier;
import io.javacryptokit.oauth.AccessTokens;
import io.javacryptokit.oauth.ClientCredentials;
import io.javacryptokit.oauth.IntrospectionResult;
import io.javacryptokit.oauth.TokenIntrospector;
import io.javacryptokit.oauth.TokenResponse;
import java.net.URI;
import java.nio.file.Path;
import java.time.Clock;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static io.javacryptokit.cli.ApiInput.problem;

/** Connects the CLI to the existing HTTPS clients and local Access Token API. */
final class ApiOAuth {
    // TokenIntrospector caps the Java string length. An ASCII token uses one byte per character.
    private static final int INTROSPECTION_TOKEN_LIMIT = 16 * 1024;

    private ApiOAuth() { }

    static int run(String action, ApiInput a) throws Exception {
        switch (action) {
            case "token": return token(a);
            case "introspect": return introspect(a);
            case "create": return create(a);
            case "verify": return verify(a);
            default: throw new IllegalStateException("oauth command");
        }
    }

    private static int token(ApiInput a) throws Exception {
        Path out = a.target(true);
        String endpoint = a.ask("endpoint");
        String clientId = a.ask("client-id");
        String auth = a.choice("auth-method", "basic", "basic", "post");
        ClientCredentials.Builder builder;
        try {
            builder = ClientCredentials.builder(URI.create(endpoint));
        } catch (IllegalArgumentException e) {
            throw ApiInput.invalid("api.err.endpoint");
        }
        builder.connectTimeout(a.seconds("connect-timeout", 5, 1, 60))
                .readTimeout(a.seconds("read-timeout", 10, 1, 120))
                .maxResponseBytes(a.integer("max-response-bytes", 64 * 1024, 1024, 1024 * 1024));
        char[] secret = a.password("client-secret-file");
        try {
            if (auth.equals("basic")) builder.clientSecretBasic(clientId, secret);
            else builder.clientSecretPost(clientId, secret);
        } catch (IllegalArgumentException e) {
            throw ApiInput.invalid("api.err.clientCredentials");
        }
        ClientCredentials client = builder.build();
        TokenResponse result;
        try {
            result = a.value("scope") == null ? client.requestToken() : client.requestToken(permissionNames(a.required("scope")));
        } catch (IllegalArgumentException e) {
            throw ApiInput.invalid("api.err.scope");
        }
        a.result(out, result.accessToken(), true);
        Map<String, Object> metadata = new LinkedHashMap<>();
        metadata.put("token_type", result.tokenType());
        metadata.put("expires_in", result.expiresIn().isPresent() ? result.expiresIn().getAsLong() : null);
        metadata.put("scope", result.scopeInResponse() ? new java.util.ArrayList<>(result.grantedScopes()) : null);
        a.err.println(StrictJson.write(metadata));
        if (result.accessToken().length() > INTROSPECTION_TOKEN_LIMIT) {
            a.err.println("[WARN] " + Messages.get("api.warn.introspectionLimit"));
        }
        return 0;
    }

    private static int introspect(ApiInput a) throws Exception {
        Path out = a.target(true);
        String token = a.text("in", INTROSPECTION_TOKEN_LIMIT * 3 + 5, true, "api.err.introspectionLimit");
        if (token.isEmpty()) throw ApiInput.invalid("api.err.emptyToken");
        if (token.length() > INTROSPECTION_TOKEN_LIMIT) throw ApiInput.invalid("api.err.introspectionLimit");
        String hint = a.value("token-type-hint");
        if (hint != null && !hint.matches("[A-Za-z0-9_]{1,64}")) throw ApiInput.invalid("api.err.tokenHint");
        String endpoint = a.ask("endpoint");
        String clientId = a.ask("client-id");
        TokenIntrospector.Builder builder;
        try {
            builder = TokenIntrospector.builder(URI.create(endpoint));
        } catch (IllegalArgumentException e) {
            throw ApiInput.invalid("api.err.endpoint");
        }
        builder.connectTimeout(a.seconds("connect-timeout", 5, 1, 60))
                .readTimeout(a.seconds("read-timeout", 10, 1, 120))
                .maxResponseBytes(a.integer("max-response-bytes", 64 * 1024, 1024, TokenIntrospector.MAX_RESPONSE_LIMIT));
        TokenIntrospector client;
        char[] secret = a.password("client-secret-file");
        try {
            client = builder.clientSecretBasic(clientId, secret).build();
        } catch (IllegalArgumentException e) {
            throw ApiInput.invalid("api.err.clientCredentials");
        }
        IntrospectionResult result = client.introspect(token, hint);
        Map<String, Object> metadata = new LinkedHashMap<>();
        metadata.put("active", result.active());
        if (result.active()) {
            metadata.put("scope", new java.util.ArrayList<>(result.scopes()));
            metadata.put("client_id", result.clientId());
            metadata.put("username", result.username());
            metadata.put("token_type", result.tokenType());
            metadata.put("sub", result.subject());
            metadata.put("iss", result.issuer());
            metadata.put("aud", result.audience());
            metadata.put("jti", result.jwtId());
            metadata.put("exp", result.expiresAt() == null ? null : result.expiresAt().getEpochSecond());
            metadata.put("iat", result.issuedAt() == null ? null : result.issuedAt().getEpochSecond());
            metadata.put("nbf", result.notBefore() == null ? null : result.notBefore().getEpochSecond());
        }
        a.jsonResult(out, metadata, true);
        return 0;
    }

    /** Split only on spaces so the OAuth validators can reject control characters. */
    private static String[] permissionNames(String value) {
        return value.replaceAll("^ +| +$", "").split(" +");
    }

    private static int create(ApiInput a) throws Exception {
        a.choice("profile", "rfc9068", "rfc9068");
        Path out = a.target(true);
        JwtAlgorithm algorithm = ApiAuth.algorithm(a);
        Clock clock = ApiAuth.clock(a, "issued-at");
        AccessTokens.Builder builder = AccessTokens.builder(clock)
                .issuer(a.ask("issuer")).subject(a.ask("subject")).audience(ApiAuth.words(a.ask("audience")))
                .clientId(a.ask("client-id")).expiresIn(a.seconds("expires-in", 300, 1, Integer.MAX_VALUE));
        if (a.value("jwt-id") != null) builder.jwtId(a.required("jwt-id"));
        if (a.value("scope") != null) builder.scopes(permissionNames(a.required("scope")));
        if (a.value("roles") != null) builder.roles(Arrays.asList(permissionNames(a.required("roles"))));
        for (Map.Entry<?, ?> claim : ApiAuth.claims(a).entrySet()) {
            String name = (String) claim.getKey();
            Object value = claim.getValue();
            if (value instanceof String) builder.claim(name, (String) value);
            else if (value instanceof Long) builder.claim(name, (Long) value);
            else if (value instanceof Boolean) builder.claim(name, (Boolean) value);
            else throw problem("api.err.claims");
        }
        a.result(out, builder.sign(ApiAuth.signingKey(a, algorithm)), true);
        return 0;
    }

    private static int verify(ApiInput a) throws Exception {
        boolean standard = "rfc9068".equals(a.choice("profile", "rfc9068", "rfc9068", "profile"));
        if (standard) a.excludes("client-id-claim", "typ", "scope-claim", "roles-claim");
        JwtAlgorithm algorithm = ApiAuth.algorithm(a);
        String issuer = a.ask("issuer");
        String audience = a.ask("audience");
        List<JwtKey> trust = ApiAuth.verificationKeys(a, algorithm);
        AccessTokenVerifier.Builder builder = (standard ? AccessTokenVerifier.rfc9068() : AccessTokenVerifier.profile())
                .issuer(issuer).audience(audience).keys(trust)
                .clock(ApiAuth.clock(a, "at")).clockSkew(a.seconds("clock-skew", 0, 0, 300));
        if (a.value("typ") != null) builder.types(ApiAuth.words(a.required("typ")));
        if (a.value("require-claims") != null) builder.requireClaims(ApiAuth.words(a.required("require-claims")));
        Map<String, String> expected = ApiAuth.expectedClaims(a);
        if (a.value("subject") != null) ApiAuth.expected(expected, "sub", a.required("subject"));
        if (a.value("forbid-claim") != null) builder.forbidClaims(ApiAuth.words(a.required("forbid-claim")));
        if (a.value("scope-claim") != null) builder.scopeClaim(a.required("scope-claim"));
        if (a.value("roles-claim") != null) builder.rolesClaim(a.required("roles-claim"));
        String clientIdClaim = a.value("client-id-claim");
        if (!standard && a.value("client-id") != null) clientIdClaim = a.ask("client-id-claim");
        else if (clientIdClaim != null) clientIdClaim = a.required("client-id-claim");
        if (clientIdClaim != null) builder.clientIdClaim(clientIdClaim);
        if (a.flag("require-permission")) builder.requirePermissionClaim(true);
        if (a.value("scope") != null) builder.requireScopes(permissionNames(a.required("scope")));
        if (a.value("roles") != null) builder.requireRoles(permissionNames(a.required("roles")));
        if (a.value("client-id") != null) {
            ApiAuth.expected(expected, standard ? "client_id" : clientIdClaim, a.required("client-id"));
        }
        expected.forEach(builder::requireClaimValue);
        AccessTokenVerifier verifier;
        try {
            verifier = builder.build();
        } catch (IllegalArgumentException e) {
            throw ApiInput.invalid(standard ? "api.err.oauthVerifier" : "api.err.oauthProfile");
        }
        String token = ApiAuth.token(a);
        try {
            return ApiAuth.verifyKid(a, verifier.verify(token).jwt().keyId());
        } catch (io.javacryptokit.jwt.JwtException e) {
            return ApiAuth.rejected(a, e.getReason());
        }
    }
}

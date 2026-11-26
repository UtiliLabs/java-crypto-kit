package io.javacryptokit.cli;

import java.io.PrintStream;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.EnumMap;
import java.util.Map;
import java.util.LinkedHashSet;
import java.util.Set;

/** Registry for the independent API commands. Authentication still runs in CryptoCli. */
final class ApiCommands {
    enum Purpose { ENCRYPTION, VERIFICATION, UTILITIES, KEYS, AUTHENTICATION }

    private static final Map<Purpose, List<CliCommands.Spec>> BY_PURPOSE = definitions();
    static final List<CliCommands.Spec> ALL = allCommands();

    private ApiCommands() { }

    private static Map<Purpose, List<CliCommands.Spec>> definitions() {
        Map<Purpose, List<CliCommands.Spec>> commands = new EnumMap<>(Purpose.class);
        String aes = "type format algorithm kdf salt salt-file iterations key-encoding key-file pass-file aad aad-file key-id in out";
        add(commands, Purpose.ENCRYPTION, "aes encrypt", true, aes + " encoding", "");
        add(commands, Purpose.ENCRYPTION, "aes decrypt", true, aes + " input-encoding", "show");
        add(commands, Purpose.ENCRYPTION, "rsa encrypt", false, "algorithm public-key in out encoding", "");
        add(commands, Purpose.ENCRYPTION, "rsa decrypt", true, "algorithm private-key in out input-encoding", "show");
        add(commands, Purpose.ENCRYPTION, "hybrid encrypt", false, "public-key in out aad aad-file encoding", "");
        add(commands, Purpose.ENCRYPTION, "hybrid decrypt", true, "private-key in out aad aad-file input-encoding", "show");
        String hmac = "algorithm key-file key-encoding in encoding";
        add(commands, Purpose.VERIFICATION, "hmac sign", true, hmac + " out", "external-key");
        add(commands, Purpose.VERIFICATION, "hmac verify", true, hmac + " expected-file", "external-key");
        add(commands, Purpose.VERIFICATION, "hash generate", false, "algorithm in encoding out", "");
        add(commands, Purpose.VERIFICATION, "hash verify", false, "algorithm in encoding expected-file", "");
        add(commands, Purpose.UTILITIES, "encode", false, "encoding in out", "");
        add(commands, Purpose.UTILITIES, "decode", false, "encoding in out", "");
        add(commands, Purpose.UTILITIES, "random bytes", true, "length encoding out", "show");
        add(commands, Purpose.UTILITIES, "random token", true, "length encoding out", "show");
        add(commands, Purpose.UTILITIES, "random string", true, "length alphabet prefix out", "show");
        add(commands, Purpose.UTILITIES, "random nonce", false, "out", "");
        add(commands, Purpose.UTILITIES, "random uuid", false, "out", "");
        add(commands, Purpose.UTILITIES, "password hash", true, "algorithm iterations password-file out", "show");
        add(commands, Purpose.UTILITIES, "password verify", true, "password-file in", "");
        add(commands, Purpose.UTILITIES, "password needs-rehash", true, "algorithm iterations in", "");
        add(commands, Purpose.UTILITIES, "kdf pbkdf2", true, "algorithm iterations salt salt-file length encoding pass-file out", "show");
        add(commands, Purpose.UTILITIES, "kdf hkdf", true, "algorithm salt salt-file info info-file length encoding key-encoding key-file out", "show");
        add(commands, Purpose.VERIFICATION, "signature sign", true, "algorithm private-key encoding in out", "");
        add(commands, Purpose.VERIFICATION, "signature verify", false, "algorithm public-key encoding in signature-file", "");
        add(commands, Purpose.KEYS, "certificate info", false, "in at out", "");
        add(commands, Purpose.KEYS, "keygen", true, "type algorithm bits encoding out reason", "show");
        add(commands, Purpose.KEYS, "keyconvert", true, "type format in out", "");
        String signer = "algorithm key-file key-encoding private-key issuer subject audience expires-in jwt-id kid claims-file out";
        String verifier = "algorithm key-file key-encoding public-key jwks-file issuer subject audience kid clock-skew require-claims require-claim-values-file in at";
        add(commands, Purpose.AUTHENTICATION, "jwt create", true, signer + " issued-at not-before", "show");
        add(commands, Purpose.AUTHENTICATION, "jwt inspect", true, "in out", "show");
        add(commands, Purpose.AUTHENTICATION, "jwt verify", true, verifier + " typ", "any-audience");
        String https = "endpoint client-id client-secret-file connect-timeout read-timeout max-response-bytes";
        add(commands, Purpose.AUTHENTICATION, "oauth token", true, https + " auth-method scope out", "show");
        add(commands, Purpose.AUTHENTICATION, "oauth introspect", true, https + " in token-type-hint out", "show");
        add(commands, Purpose.AUTHENTICATION, "oauth create", true, signer + " profile client-id scope roles issued-at", "show");
        add(commands, Purpose.AUTHENTICATION, "oauth verify", true, verifier + " profile typ scope roles client-id client-id-claim scope-claim roles-claim forbid-claim",
                "require-permission");
        String otp = "type algorithm digits period key-file";
        add(commands, Purpose.AUTHENTICATION, "otp generate", true, otp + " counter at out", "show");
        add(commands, Purpose.AUTHENTICATION, "otp verify", true, otp + " counter at window in", "");
        add(commands, Purpose.AUTHENTICATION, "otp uri", true, otp + " issuer account out", "show");
        String request = "algorithm key-file key-encoding in at";
        add(commands, Purpose.AUTHENTICATION, "request-auth sign", true, request + " out", "");
        add(commands, Purpose.AUTHENTICATION, "request-auth verify", true, request + " clock-skew auth-file timestamp nonce mac", "");
        return commands;
    }

    private static List<CliCommands.Spec> allCommands() {
        List<CliCommands.Spec> commands = new ArrayList<>();
        BY_PURPOSE.values().forEach(commands::addAll);
        return Collections.unmodifiableList(commands);
    }

    private static void add(Map<Purpose, List<CliCommands.Spec>> commands, Purpose purpose, String path, boolean admin,
                            String values, String flags) {
        List<String> options = options(values);
        if (admin) options.add(CliCommands.ADMIN_FILE);
        commands.computeIfAbsent(purpose, key -> new ArrayList<>()).add(new CliCommands.Spec("api " + path, "api-" + path.replace(' ', '-'), options, options(flags), false,
                admin ? CliCommands.Access.ADMIN : CliCommands.Access.OPEN));
    }

    private static List<String> options(String words) {
        List<String> result = new ArrayList<>();
        if (!words.isEmpty()) for (String word : words.split(" ")) result.add("--" + word);
        return result;
    }

    static Set<String> groups() {
        return groups(ALL);
    }

    static Set<String> groups(Purpose purpose) {
        return groups(BY_PURPOSE.get(purpose));
    }

    private static Set<String> groups(List<CliCommands.Spec> commands) {
        Set<String> groups = new LinkedHashSet<>();
        for (CliCommands.Spec spec : commands) groups.add(spec.name.split(" ")[1]);
        return groups;
    }

    static int run(CliCommands.Parsed args, CryptoCli.TerminalProvider terminals, PrintStream out, PrintStream err)
            throws Exception {
        try (ApiInput input = new ApiInput(args, terminals, out, err)) {
            String[] path = args.spec.name.split(" ");
            String action = path.length == 3 ? path[2] : "";
            int code;
            switch (path[1]) {
                case "aes": case "rsa": case "hybrid": case "signature": case "keygen":
                case "keyconvert": case "certificate":
                    code = ApiCrypto.run(path[1], action, input);
                    break;
                case "jwt": case "oauth": case "otp": case "request-auth":
                    code = ApiAuth.run(path[1], action, input);
                    break;
                default:
                    code = ApiUtilities.run(path[1], action, input);
            }
            if (code == 0) input.printReceipt();
            return code;
        }
    }
}

package io.javacryptokit.cli;

import io.javacryptokit.CredentialCrypto;
import io.javacryptokit.TestJars;
import io.javacryptokit.TestKeytool;
import io.javacryptokit.i18n.Messages;
import io.javacryptokit.jwt.Jwt;
import io.javacryptokit.jwt.JwtKey;
import io.javacryptokit.oauth.AccessTokenVerifier;
import io.javacryptokit.security.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.time.Instant;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import static org.junit.jupiter.api.Assertions.*;

class ApiCliTest {
    @TempDir Path dir;
    private final CliHarness cli = new CliHarness();

    @AfterEach
    void close() throws Exception {
        cli.close();
    }

    private Path f(String name) {
        return dir.resolve(name);
    }

    private Path input(String name, String text) throws Exception {
        Path p = Files.write(f(name), Bytes.utf8(text));
        if (p.getFileSystem().supportedFileAttributeViews().contains("posix")) {
            Files.setPosixFilePermissions(p, PosixFilePermissions.fromString("rw-------"));
        }
        return p;
    }

    private String text(String name) throws Exception {
        return Bytes.utf8String(Files.readAllBytes(f(name))).trim();
    }

    private void ok(String... args) {
        assertEquals(0, run(args), cli.err());
    }

    private int run(String... args) {
        String[] resolved = Arrays.copyOf(args, args.length);
        for (int i = 0; i < resolved.length; i++) {
            if (resolved[i].startsWith("@")) resolved[i] = f(resolved[i].substring(1)).toString();
        }
        return cli.run(resolved);
    }

    private void keygen(String type, String name, String... options) {
        String[] args = {"api", "keygen", "--type", type, "--out", "@" + name, "--reason", "fixture"};
        String[] all = Arrays.copyOf(args, args.length + options.length);
        System.arraycopy(options, 0, all, args.length, options.length);
        ok(all);
    }

    @Test
    void jwtCreationWithTooManyFinalClaimsLeavesNoOutput() throws Exception {
        input("claims-signing.key", Encoding.BASE64.encode(Hmac.generateKey()));
        java.util.Map<String, Object> claims = new java.util.LinkedHashMap<>();
        for (int i = 0; i < 999; i++) claims.put("c" + i, i);
        input("claims.json", io.javacryptokit.json.StrictJson.write(claims));
        assertEquals(1, run("api", "jwt", "create", "--algorithm", "hs256", "--key-file", "@claims-signing.key",
                "--claims-file", "@claims.json", "--out", "@invalid.jwt"));
        assertFalse(Files.exists(f("invalid.jwt")));
        claims.remove("c998");
        input("claims.json", io.javacryptokit.json.StrictJson.write(claims));
        ok("api", "jwt", "create", "--algorithm", "hs256", "--key-file", "@claims-signing.key",
                "--claims-file", "@claims.json", "--out", "@valid.jwt");
        assertEquals(997L, Jwt.parseUnverified(text("valid.jwt")).claims().getLong("c997").longValue());
    }

    @Test
    void allQueriesAndExamplesFollowRegistryWithoutAuthentication() throws Exception {
        Path jar = TestJars.build(f("api test.jar"));
        cli.withCliJar(jar);
        byte[] original = Files.readAllBytes(jar);
        Set<String> names = new HashSet<>();
        Set<String> exercised = new HashSet<>();
        for (String lang : new String[] {"ko", "en"}) {
            ok("api", "--help", "--lang", lang);
            for (ApiCommands.Purpose purpose : ApiCommands.Purpose.values()) {
                assertTrue(cli.out().contains(Messages.get(Messages.Language.fromCode(lang),
                        "api.help.purpose." + purpose.name())), cli.out());
            }
            for (String group : ApiCommands.groups()) {
                assertEquals(1, Arrays.stream(cli.out().split("\\R"))
                        .filter(line -> line.startsWith("  api " + group + " --help ")).count(), group);
            }
            assertFalse(cli.out().contains("!api."), cli.out());
            for (String line : cli.out().split("\\R")) assertTrue(CliHelp.width(line) <= 80, line);
            for (CliCommands.Spec spec : ApiCommands.ALL) {
                names.add(spec.name);
                assertSame(spec, CliCommands.find(spec.name));
                String[] path = spec.name.split(" ");
                String[] help = Arrays.copyOf(path, path.length + 3);
                help[path.length] = "--help";
                help[path.length + 1] = "--lang";
                help[path.length + 2] = lang;
                ok(help);
                assertTrue(cli.out().contains(spec.name), cli.out());
                for (String opt : spec.options()) assertTrue(cli.out().contains(opt), opt + " " + spec.name);
                if (spec.name.equals("api oauth create") || spec.name.equals("api oauth verify")) {
                    assertFalse(cli.out().contains("--read-timeout"), cli.out());
                    assertFalse(cli.out().contains("HTTPS"), cli.out());
                }
                for (String line : cli.out().split("\\R")) {
                    assertFalse(line.contains("!api."), line);
                    assertTrue(CliHelp.width(line) <= 80, line);
                }
                help[path.length] = "--examples";
                ok(help);
                String example = Messages.get(Messages.Language.fromCode(lang), "api.example." + spec.topic);
                assertTrue(cli.out().contains("java -jar \"api test.jar\" api "), cli.out());
                assertFalse(cli.out().contains("java -jar \"api test-cfg.jar\" api "), cli.out());
                assertTrue(cli.out().contains(updatePrefix("api test.jar") + " admin setup"), cli.out());
                assertTrue(checkExampleLines(example).contains(spec.name), example);
                exercised.add(spec.name);
            }
            for (String family : ApiCommands.groups()) {
                ok("api", family, "--help", "--lang", lang);
                ok("api", family, "--examples", "--lang", lang);
                assertTrue(cli.out().contains("java -jar"));
                String key = "api.flow." + family;
                Messages.Language language = Messages.Language.fromCode(lang);
                if (Messages.has(language, key)) checkExampleLines(Messages.get(language, key));
            }
        }
        assertEquals(39, names.size());
        assertEquals(18, ApiCommands.groups().size());
        assertEquals(names, exercised);
        assertArrayEquals(original, Files.readAllBytes(jar));
    }

    private static Set<String> checkExampleLines(String examples) throws Exception {
        Set<String> names = new HashSet<>();
        java.util.regex.Pattern word = java.util.regex.Pattern.compile("'[^']*'|\"[^\"]*\"|\\S+");
        for (String line : examples.split("\\R")) {
            if (!line.startsWith("java -jar {jar} api ")) continue;
            java.util.List<String> args = new java.util.ArrayList<>();
            java.util.regex.Matcher matcher = word.matcher(line.substring("java -jar {jar} ".length()));
            while (matcher.find()) {
                String item = matcher.group();
                args.add(item.startsWith("'") || item.startsWith("\"") ? item.substring(1, item.length() - 1) : item);
            }
            int end = 1;
            while (end < args.size() && !args.get(end).startsWith("--")) end++;
            CliCommands.Spec spec = CliCommands.find(String.join(" ", args.subList(0, end)));
            assertNotNull(spec, line);
            CliCommands.parse(spec, args.toArray(new String[0]), end);
            names.add(spec.name);
        }
        return names;
    }

    @Test
    void configuredHelpAndExamplesDoNotUseExternalSettings() throws Exception {
        Path jar = CliHarness.configure(TestJars.build(f("configured app.jar")), CliHarness.ADMIN_PASSWORD);
        cli.withCliJar(jar);
        byte[] original = Files.readAllBytes(jar);
        String property = io.javacryptokit.config.CryptoSettings.CONFIG_FILE_PROPERTY;
        String previous = System.setProperty(property, f("missing-config.properties").toString());
        try {
            for (String lang : new String[] {"en", "ko"}) {
                ok("--help", "--lang", lang);
                assertTrue(cli.out().contains("-jar \"configured app.jar\""), cli.out());
                ok("file", "--examples", "--lang", lang);
                assertTrue(cli.out().contains("java -jar \"configured app.jar\" file dec"), cli.out());
                assertFalse(cli.out().contains("admin setup --operator"), cli.out());
                ok("config", "key", "add", "--help", "--lang", lang);
                assertTrue(cli.out().contains("--key-id"), cli.out());
                ok("api", "jwt", "--help", "--lang", lang);
                assertTrue(cli.out().contains("api jwt verify"), cli.out());
                ok("api", "jwt", "verify", "--examples", "--lang", lang);
                assertTrue(cli.out().contains("java -jar \"configured app.jar\" api jwt verify"), cli.out());
                assertFalse(cli.out().contains("admin setup --operator"), cli.out());
            }
            assertEquals(1, run("api", "oauth", "token", "--help", "--out", "@forbidden"));
            assertFalse(Files.exists(f("forbidden")));
            assertArrayEquals(original, Files.readAllBytes(jar));
        } finally {
            if (previous == null) System.clearProperty(property);
            else System.setProperty(property, previous);
        }
    }

    private static String updatePrefix(String file) {
        return "java -jar \"" + file + "\"";
    }

    @Test
    void managedAndApiExamplesShareSetupGuidanceWithoutUsingConfiguredJarForSetup() throws Exception {
        Path fresh = TestJars.build(f("sample release.jar"));
        cli.withCliJar(fresh);
        byte[] original = Files.readAllBytes(fresh);
        for (Messages.Language language : Messages.Language.values()) {
            String lang = language == Messages.Language.KO ? "ko" : "en";
            String prelude = Messages.get(language, "cli.examples.setup").replace("{jar}", "\"sample release.jar\"")
                    .replace("{update}", updatePrefix("sample release.jar"));
            ok("file", "--examples", "--lang", lang);
            assertTrue(cli.out().startsWith(prelude), cli.out());
            String operational = "java -jar \"sample release.jar\" ";
            assertTrue(cli.out().contains(operational + "file enc --in") && cli.out().contains(operational + "file dec --in"), cli.out());
            ok("api", "otp", "--examples", "--lang", lang);
            assertTrue(cli.out().startsWith(prelude), cli.out());
            assertTrue(cli.out().contains(operational + "api otp gen") && cli.out().contains(operational + "api otp verify"), cli.out());
            assertFalse(cli.out().contains("java -jar \"sample release-cfg.jar\" api "), cli.out());
            ok("admin", "--examples", "--lang", lang);
            assertTrue(cli.out().contains(updatePrefix("sample release.jar") + " admin setup"), cli.out());
            assertTrue(cli.out().contains(updatePrefix("sample release.jar") + " admin password change"), cli.out());
            ok("config", "embed-key", "--examples", "--lang", lang);
            assertTrue(cli.out().contains(updatePrefix("sample release.jar") + " config embed-key"), cli.out());
            assertTrue(cli.out().contains("java -jar \"sample release.jar\" fingerprint"), cli.out());
            ok("--examples", "--lang", lang);
            assertTrue(cli.out().startsWith(prelude), cli.out());
            ok("api", "--examples", "--lang", lang);
            assertTrue(cli.out().startsWith(prelude), cli.out());
            ok("admin", "setup", "--examples", "--lang", lang);
            assertTrue(cli.out().startsWith(Messages.get(language, "cli.examples.setupOnly")), cli.out());
            assertTrue(cli.out().contains(updatePrefix("sample release.jar") + " admin setup"), cli.out());
            assertFalse(cli.out().contains("admin setup --operator example"), cli.out());
        }

        Path configured = CliHarness.configure(Files.copy(fresh, f("renamed.jar")), CliHarness.ADMIN_PASSWORD);
        cli.withCliJar(configured);
        byte[] configuredBytes = Files.readAllBytes(configured);
        for (String lang : new String[] {"ko", "en"}) {
            ok("admin", "--examples", "--lang", lang);
            assertTrue(cli.out().contains(updatePrefix("java-crypto-kit-" + CliHelp.version() + ".jar") + " admin setup"), cli.out());
            assertFalse(cli.out().contains("\"renamed.jar\" admin setup"), cli.out());
            assertTrue(cli.out().contains("\"renamed.jar\" admin password change"), cli.out());
        }
        assertArrayEquals(original, Files.readAllBytes(fresh));
        assertArrayEquals(configuredBytes, Files.readAllBytes(configured));
        assertFalse(Files.exists(f("sample release-cfg.jar")));
    }

    @Test
    void individualTotpExamplesRoundTripAtTheGroupTestInstant() throws Exception {
        for (Messages.Language language : Messages.Language.values()) {
            String group = Messages.get(language, "api.flow.otp");
            for (String action : new String[] {"generate", "verify"}) {
                String example = Messages.get(language, "api.example.api-otp-" + action);
                assertTrue(example.contains("--at 2026-11-26T00:00:00Z") && group.contains("--at 2026-11-26T00:00:00Z"), example);
                assertTrue(example.contains(language == Messages.Language.KO ? "시험" : "test"), example);
                assertTrue(example.contains("otp-code.txt"), example);
            }
        }
        keygen("otp", "otp.key");
        for (String action : new String[] {"generate", "verify"}) {
            String example = Messages.get(Messages.Language.EN, "api.example.api-otp-" + action);
            String command = Arrays.stream(example.split("\\R")).filter(line -> line.startsWith("java -jar {jar} api ")).findFirst().get();
            String[] args = command.substring("java -jar {jar} ".length()).split(" ");
            for (int i = 0; i < args.length; i++) {
                if (args[i].equals("otp.key") || args[i].equals("otp-code.txt")) args[i] = "@" + args[i];
            }
            ok(args);
        }
        assertEquals("OK", cli.out().trim());
    }

    @Test
    void adminBeforeSecretsAndNoKeyringMutation() throws Exception {
        Path jar = CliHarness.configure(TestJars.build(f("configured.jar")), CliHarness.ADMIN_PASSWORD);
        cli.withCliJar(jar);
        Path wrong = input("wrong.pw", "WrongPassword1!");
        input("right.pw", CliHarness.ADMIN_PASSWORD);
        byte[] original = Files.readAllBytes(jar);
        assertEquals(1, run("api", "random", "token", "--out", "@blocked", "--admin-pass-file", wrong.toString()));
        assertTrue(cli.err().contains("ADMIN_AUTH"), cli.err());
        assertFalse(Files.exists(f("blocked")));
        assertTrue(cli.out().isEmpty());
        ok("api", "random", "token", "--out", "@token", "--admin-pass-file", "@right.pw");
        assertTrue(cli.out().isEmpty());
        assertArrayEquals(original, Files.readAllBytes(jar));
        assertEquals(1, run("api", "random", "token", "--admin-pass-file", "@right.pw"));
        assertEquals(1, run("api", "random", "uuid", "--examples", "--out", "@never"));
        assertFalse(Files.exists(f("never")));
        assertEquals(1, run("api", "random", "token", "--out", "@token", "--out", "@other",
                "--admin-pass-file", "@right.pw"));
        assertFalse(Files.exists(f("other")));
    }

    @Test
    void interactiveUsesHiddenInputAndRequiresExplicitDisplayApproval() {
        CliHarness.FakeTerminal t = new CliHarness.FakeTerminal();
        t.lines.add("SHOW");
        assertEquals(0, cli.run(t, "api", "random", "string", "--show", "--length", "8", "--alphabet", "digits"));
        assertTrue(cli.out().isEmpty());
        assertTrue(t.printed.stream().anyMatch(x -> x.matches("[0-9]{8}")), t.printed.toString());
        CliHarness.FakeTerminal hidden = new CliHarness.FakeTerminal();
        hidden.secrets.add(Encoding.BASE64.encode(new byte[32]));
        hidden.secrets.add("fixture plaintext");
        assertEquals(0, cli.run(hidden, "api", "aes", "encrypt"));
        assertEquals(2, hidden.prompts.size());
        assertTrue(hidden.prompts.get(0).contains("AES Key (Base64, 입력 숨김)"), hidden.prompts.toString());
        assertTrue(hidden.prompts.get(1).contains("암호화할 원문 (입력 숨김)"), hidden.prompts.toString());
        assertFalse(cli.out().contains("fixture plaintext"));
        assertTrue(hidden.secrets.isEmpty());

    }

    @Test
    void aliasesResolveToTheSameSpecsAndOptionValues() throws Exception {
        java.util.List<CliCommands.Spec> all = new java.util.ArrayList<>(CliCommands.ALL);
        all.addAll(ApiCommands.ALL);
        Set<String> seen = new HashSet<>();
        Set<String> shortOptions = new HashSet<>();
        Path fresh = TestJars.build(f("alias fresh.jar"));
        cli.withCliJar(fresh);
        for (CliCommands.Spec spec : all) {
            String alias = CliCommands.commandAlias(spec.name);
            if (alias != null) {
                assertTrue(seen.add(alias), alias);
                assertSame(spec, CliCommands.find(alias));
                for (String lookup : new String[] {"--help", "--examples"}) {
                    String[] base = alias.split(" ");
                    String[] command = Arrays.copyOf(base, base.length + 1);
                    command[base.length] = lookup;
                    ok(command);
                    assertFalse(cli.out().isEmpty(), alias);
                }
            }
            for (String name : spec.values) {
                String shortName = CliCommands.optionAlias(spec, name);
                if (shortName == null) continue;
                shortOptions.add(shortName);
                assertFalse(spec.options().contains(shortName), spec.name);
                String value = "value=--alg=untouched";
                assertEquals(value, CliCommands.parse(spec, new String[]{shortName, value}, 0).value(name));
                assertEquals(value, CliCommands.parse(spec, new String[]{shortName + "=" + value}, 0).value(name));
                assertThrows(CryptoCli.CliException.class,
                        () -> CliCommands.parse(spec, new String[]{shortName, value, name, value}, 0));
            }
        }
        assertEquals(23, seen.size());
        assertEquals(17, shortOptions.size());
        for (String group : new String[]{"sig", "cert", "rand", "req-auth"}) {
            ok("api", group, "--help");
            ok("api", group, "--examples");
        }
        assertEquals(1, run("api", "rand", "uuid"));
        assertTrue(cli.err().contains("ADMIN_SETUP"), cli.err());

        Path configured = CliHarness.configure(TestJars.build(f("alias-configured.jar")), CliHarness.ADMIN_PASSWORD);
        cli.withCliJar(configured);
        input("bad-admin.pw", "Wrong-password1!");
        assertEquals(1, run("api", "rand", "token", "--len", "16", "--out", "@blocked", "--admin-pass-file", "@bad-admin.pw"));
        assertTrue(cli.err().contains("ADMIN_AUTH"), cli.err());
        assertFalse(Files.exists(f("blocked")));
        input("input.txt", "content");
        ok("api", "hash", "gen", "--alg=sha256", "--encoding", "hex", "--in", "@input.txt");
        assertEquals(Digests.sha256Hex(Bytes.utf8("content")), cli.out().trim());
        assertEquals(1, run("api", "rand", "uuid", "--alg=sha256"));
        assertEquals(1, run("api", "otp", "uri", "--iss", "not-a-token-claim"));
        assertEquals(1, run("api", "Jwt", "verify"));
    }

    @Test
    void interactiveJwtAsksForAudienceAndHandlesEofAndExplicitPolicy() throws Exception {
        keygen("hmac", "interactive.key");
        ok("api", "jwt", "create", "--alg=hs256", "--key-file", "@interactive.key", "--aud", "svc", "--out", "@interactive.jwt");
        String signed = text("interactive.jwt");
        CliHarness.FakeTerminal terminal = new CliHarness.FakeTerminal();
        terminal.lines.add("hs256");
        terminal.lines.add("svc");
        terminal.secrets.add(text("interactive.key"));
        terminal.secrets.add(signed);
        assertEquals(0, cli.run(terminal, "api", "jwt", "verify", "--lang", "en"), cli.err());
        assertEquals("OK", cli.out().trim());
        assertTrue(terminal.prompts.get(0).contains("hs256 / rs256 / es256"));
        assertTrue(terminal.prompts.get(1).contains("Expected audience"));
        assertTrue(terminal.prompts.get(2).contains("Base64, hidden"));
        assertTrue(terminal.prompts.get(3).contains("Compact JWT to verify (hidden)"));
        assertFalse(terminal.prompts.toString().contains(signed));

        CliHarness.FakeTerminal eof = new CliHarness.FakeTerminal();
        assertEquals(1, cli.run(eof, "api", "jwt", "verify", "--alg", "hs256", "--lang", "en"));
        assertEquals(1, eof.prompts.size());
        assertTrue(cli.err().contains("Provide --audience"), cli.err());
        assertTrue(cli.out().isEmpty());
        assertEquals(1, run("api", "jwt", "verify", "--alg", "hs256", "--lang", "en"));
        assertTrue(cli.err().contains("Provide --audience"), cli.err());
        assertEquals(1, run("api", "jwt", "verify", "--alg", "hs256", "--aud", "svc", "--any-audience"));
        CliHarness.FakeTerminal explicit = new CliHarness.FakeTerminal();
        assertEquals(0, cli.run(explicit, "api", "jwt", "verify", "--alg", "hs256", "--any-audience",
                "--key-file", f("interactive.key").toString(), "--in", f("interactive.jwt").toString()), cli.err());
        assertTrue(explicit.prompts.isEmpty());
    }

    @Test
    void successfulInteractiveFileReceiptUsesBasenamesAndOnlyAppearsAfterPublication() throws Exception {
        keygen("hmac", "receipt.key");
        CliHarness.FakeTerminal terminal = new CliHarness.FakeTerminal();
        terminal.lines.add(f("result token.txt").toString());
        assertEquals(0, cli.run(terminal, "api", "jwt", "create", "--alg", "hs256", "--key-file",
                f("receipt.key").toString(), "--aud", "svc", "--lang", "en"), cli.err());
        assertTrue(terminal.prompts.get(0).contains("Output file path"));
        assertTrue(cli.out().isEmpty());
        assertTrue(cli.err().contains("[OK] JWT created") && cli.err().contains("Saved file: result token.txt"), cli.err());
        assertFalse(cli.err().contains(dir.toString()));
        assertFalse(cli.err().contains(text("result token.txt")));

        CliHarness.FakeTerminal pair = new CliHarness.FakeTerminal();
        assertEquals(0, cli.run(pair, "api", "keygen", "--type", "ec", "--out", f("demo").toString(),
                "--reason", "fixture", "--lang", "ko"), cli.err());
        assertTrue(cli.err().contains("[OK]") && cli.err().contains("공개키: demo-public.pem")
                && cli.err().contains("개인키: demo-private.pem"), cli.err());
        assertTrue(Files.exists(f("demo-private.pem")));
        assertEquals(1, cli.run(pair, "api", "keygen", "--type", "ec", "--out", f("demo").toString(),
                "--reason", "fixture", "--lang", "en"));
        assertFalse(cli.err().contains("[OK]"), cli.err());
        assertTrue(cli.out().isEmpty());
        ok("api", "keygen", "--type", "ec", "--out", "@batch", "--reason", "fixture");
        assertTrue(cli.out().isEmpty() && cli.err().isEmpty());
    }

    @Test
    void otpKeygenRejectsNonBase32AndReusesDefaultAndExplicitSecretFiles() throws Exception {
        for (String encoding : new String[] {"hex", "base64", "base64url"}) {
            assertEquals(1, run("api", "keygen", "--type", "otp", "--encoding", encoding, "--out", "@bad",
                    "--reason", "fixture", "--lang", "en"));
            assertTrue(cli.err().contains("--encoding") && cli.err().contains("base32"), cli.err());
            assertTrue(cli.out().isEmpty(), cli.out());
            assertFalse(Files.exists(f("bad")));
        }
        for (String option : new String[] {"default", "explicit"}) {
            String key = option + ".key";
            if (option.equals("default")) keygen("otp", key);
            else keygen("otp", key, "--encoding", "base32");
            String time = "2026-11-26T00:00:00Z";
            ok("api", "otp", "generate", "--key-file", "@" + key, "--at", time, "--out", "@" + option + ".otp");
            assertEquals(Totp.of(Encoding.BASE32.decode(text(key))).generate(Instant.parse(time)), text(option + ".otp"));
        }
    }

    @Test
    void tokenRejectionsAreLocalizedAndInputErrorsHaveNoVerdict() throws Exception {
        keygen("hmac", "jwt.key");
        ok("api", "jwt", "create", "--algorithm", "hs256", "--key-file", "@jwt.key", "--issuer", "auth", "--audience", "svc",
                "--out", "@token");
        ok("api", "oauth", "create", "--algorithm", "hs256", "--key-file", "@jwt.key", "--issuer", "auth", "--audience", "svc",
                "--subject", "subject", "--client-id", "client", "--scope", "read", "--out", "@access");
        // 비정상 권한(제어문자가 든 역할·scope)은 발급·요구 조건 모두 입력 오류로 거부하고 결과 파일을 만들지 않는다.
        for (String[] permission : new String[][] {{"--roles", "reader\u0001"}, {"--scope", "read\u0000"}}) {
            assertEquals(1, run("api", "oauth", "create", "--algorithm", "hs256", "--key-file", "@jwt.key", "--issuer", "auth",
                    "--audience", "svc", "--subject", "subject", "--client-id", "client", permission[0], permission[1],
                    "--out", "@bad-access"), permission[0]);
            assertFalse(Files.exists(f("bad-access")), permission[0]);
            assertEquals(1, run("api", "oauth", "verify", "--algorithm", "hs256", "--key-file", "@jwt.key", "--issuer", "auth",
                    "--audience", "svc", permission[0], permission[1], "--in", "@access"), permission[0]);
            assertFalse(cli.out().trim().equals("OK"), cli.out());
        }
        input("bad.key", "not-a-valid-private-value!");
        input("bad.jwt", "sensitive.token.invalid");
        input("bad.json", "{\"key\":\"sensitive value\"");
        for (String lang : new String[] {"en", "ko"}) {
            Messages.Language language = Messages.Language.fromCode(lang);
            ok("api", "jwt", "verify", "--algorithm", "hs256", "--key-file", "@jwt.key", "--audience", "svc", "--in", "@token", "--lang", lang);
            assertEquals("OK", cli.out().trim());
            assertEquals(1, run("api", "jwt", "verify", "--algorithm", "hs256", "--key-file", "@jwt.key", "--audience", "other",
                    "--in", "@token", "--lang", lang));
            assertEquals("FAIL", cli.out().trim());
            assertTrue(cli.err().contains(Messages.get(language, "api.err.jwt.AUDIENCE")), cli.err());
            assertFalse(cli.err().contains(text("token")), cli.err());
            assertEquals(1, run("api", "oauth", "verify", "--algorithm", "hs256", "--key-file", "@jwt.key", "--issuer", "auth",
                    "--audience", "svc", "--scope", "write", "--in", "@access", "--lang", lang));
            assertEquals("FAIL", cli.out().trim());
            assertTrue(cli.err().contains(Messages.get(language, "api.err.jwt.SCOPE")), cli.err());
            assertEquals(1, run("api", "jwt", "verify", "--algorithm", "hs256", "--key-file", "@jwt.key", "--audience", "svc",
                    "--in", "@bad.jwt", "--lang", lang));
            assertEquals("FAIL", cli.out().trim());
            assertTrue(cli.err().contains("MALFORMED"), cli.err());
            assertFalse(cli.err().contains(text("bad.jwt")), cli.err());
            assertEquals(1, run("api", "jwt", "verify", "--algorithm", "hs256", "--key-file", "@bad.key", "--audience", "svc",
                    "--in", "@token", "--lang", lang));
            assertTrue(cli.out().isEmpty());
            assertTrue(cli.err().contains(Messages.get(language, "api.err.encoding", "--key-file", "BASE64")), cli.err());
            assertFalse(cli.err().contains(text("bad.key")));
            assertEquals(1, run("api", "jwt", "verify", "--algorithm", "hs256", "--key-file", "@jwt.key", "--audience", "svc",
                    "--in", "@token", "--require-claim-values-file", "@bad.json", "--lang", lang));
            assertTrue(cli.out().isEmpty());
            assertTrue(cli.err().contains(Messages.get(language, "api.err.json", "--require-claim-values-file")), cli.err());
            assertFalse(cli.err().contains("sensitive value"));
        }
    }

    @Test
    void directAesAndPassphraseMatchPublicApiBothWays() throws Exception {
        String value = "업무 데이터\r\npayload";
        input("input", value);
        input("password", "fixture passphrase");
        input("short.key", Encoding.BASE64.encode(new byte[16]));
        assertEquals(1, run("api", "aes", "enc", "--key-file", "@short.key", "--in", "@input", "--lang", "en"));
        assertTrue(cli.err().contains("AES-256-GCM requires a 32-byte key") && cli.err().contains("--key-enc"), cli.err());
        assertFalse(cli.err().contains(text("short.key")));
        assertEquals(1, run("api", "aes", "enc", "--type", "pass", "--salt", "0000",
                "--pass-file", "@password", "--in", "@input", "--lang", "en"));
        assertTrue(cli.err().contains("16 to 64 decoded bytes"), cli.err());
        byte[] salt = new byte[16];
        for (int bits : new int[] {128, 256}) {
            String label = Integer.toString(bits);
            keygen("aes", "aes" + label, "--bits", label);
            byte[] raw = Encoding.BASE64.decode(text("aes" + label));
            AesGcm api = AesGcm.of(bits == 128 ? AesKeySize.AES_128 : AesKeySize.AES_256, raw);
            ok("api", "aes", "encrypt", "--algorithm", "aes-" + label + "-gcm", "--key-file", "@aes" + label,
                    "--aad", "ctx", "--in", "@input", "--out", "@sealed" + label);
            assertArrayEquals(Bytes.utf8(value), api.decrypt(Encoding.BASE64.decode(text("sealed" + label)), Bytes.utf8("ctx")));
            input("api" + label, Encoding.BASE64.encode(api.encrypt(Bytes.utf8(value), Bytes.utf8("ctx"))));
            ok("api", "aes", "decrypt", "--algorithm", "aes-" + label + "-gcm", "--key-file", "@aes" + label,
                    "--aad", "ctx", "--in", "@api" + label, "--out", "@clear" + label);
            assertArrayEquals(Files.readAllBytes(f("input")), Files.readAllBytes(f("clear" + label)));
        }
        AesGcm derived = AesGcm.fromPassphrase(AesKeySize.AES_256, Pbkdf2Algorithm.SHA512,
                "fixture passphrase".toCharArray(), salt, 100000);
        input("pass-sealed", Encoding.BASE64.encode(derived.encrypt(Bytes.utf8(value), Bytes.utf8("ctx"))));
        String[] options = {"api", "aes", "decrypt", "--type", "pass", "--kdf", "pbkdf2-sha512",
                "--salt", Encoding.HEX.encode(salt), "--iterations", "100000", "--pass-file", "@password",
                "--aad", "ctx", "--in", "@pass-sealed", "--out", "@pass-clear"};
        ok(options);
        assertArrayEquals(Bytes.utf8(value), Files.readAllBytes(f("pass-clear")));
        options[14] = "different";
        options[18] = "@failure";
        assertEquals(1, run(options));
        assertFalse(Files.exists(f("failure")));
        options[14] = "ctx";
        options[8] = "10000000000000000000000000000000";
        assertEquals(1, run(options));
        assertTrue(cli.err().contains("INTEGRITY"), cli.err());
        assertFalse(Files.exists(f("failure")));

        ok("api", "aes", "encrypt", "--format", "enc", "--key-id", "local", "--in", "@input", "--key-file", "@aes256", "--out", "@enc");
        CredentialCrypto direct = CredentialCrypto.fromRawKey("local", Encoding.BASE64.decode(text("aes256")));
        assertArrayEquals(Bytes.utf8(value), direct.decryptBytes(text("enc")));
        input("direct.enc", direct.encryptBytes(Bytes.utf8(value)));
        ok("api", "aes", "decrypt", "--format", "enc", "--key-id", "local", "--in", "@direct.enc",
                "--key-file", "@aes256", "--out", "@direct.plain");
        assertArrayEquals(Bytes.utf8(value), Files.readAllBytes(f("direct.plain")));
        assertEquals(1, run("api", "aes", "decrypt", "--format", "enc", "--key-id", "different", "--in", "@direct.enc",
                "--key-file", "@aes256", "--out", "@wrong-id"));
        assertTrue(cli.err().contains("KEY_ID_MISMATCH"), cli.err());
        assertFalse(Files.exists(f("wrong-id")));
        ok("api", "aes", "encrypt", "--format", "enc", "--key-id", "pass-local", "--type", "pass", "--kdf",
                "pbkdf2-sha256", "--pass-file", "@password", "--salt", Encoding.HEX.encode(salt),
                "--iterations", "100000", "--in", "@input", "--out", "@pass.enc");
        CredentialCrypto passDirect = CredentialCrypto.fromPassphrase("pass-local", "fixture passphrase".toCharArray(),
                salt, 100000, Pbkdf2Algorithm.SHA256);
        assertArrayEquals(Bytes.utf8(value), passDirect.decryptBytes(text("pass.enc")));
        assertEquals(1, run("api", "aes", "encrypt", "--key-id", "local", "--in", "@input", "--key-file", "@aes256"));
        assertEquals(1, run("api", "aes", "encrypt", "--format", "enc", "--key-id", "local", "--aad", "external",
                "--in", "@input", "--key-file", "@aes256"));
        assertEquals(1, run("api", "aes", "encrypt", "--format", "enc", "--algorithm", "aes-128-gcm",
                "--key-id", "local", "--in", "@input", "--key-file", "@aes128"));
    }

    @Test
    void rsaHybridSignatureAndKeyConversionInteroperate() throws Exception {
        byte[] msg = Bytes.utf8("interoperability data");
        input("data", Bytes.utf8String(msg));
        keygen("rsa", "rsa", "--bits", "2048");
        keygen("ec", "ec");
        java.security.PrivateKey privateKey = PemKeys.readPrivateKeyFile(f("rsa-private.pem"));
        java.security.PublicKey publicKey = PemKeys.readPublicKeyFile(f("rsa-public.pem"));
        ok("api", "rsa", "encrypt", "--public-key", "@rsa-public.pem", "--algorithm", "sha512",
                "--in", "@data", "--out", "@rsa.out");
        assertArrayEquals(msg, RsaOaep.decrypt(privateKey, Encoding.BASE64.decode(text("rsa.out")), RsaOaepAlgorithm.SHA512));
        input("rsa.back", Encoding.BASE64.encode(RsaOaep.encrypt(publicKey, msg)));
        ok("api", "rsa", "decrypt", "--private-key", "@rsa-private.pem", "--in", "@rsa.back", "--out", "@rsa.clear");
        assertArrayEquals(msg, Files.readAllBytes(f("rsa.clear")));
        assertEquals(1, run("api", "rsa", "decrypt", "--private-key", "@ec-private.pem", "--in", "@rsa.back", "--out", "@no-rsa"));
        assertFalse(Files.exists(f("no-rsa")));

        input("large", new String(new char[200]).replace('\0', 'x'));
        assertEquals(1, run("api", "rsa", "encrypt", "--public-key", "@rsa-public.pem", "--in", "@large"));
        assertTrue(cli.err().contains("190") && cli.out().isEmpty(), cli.err());
        CliHarness.FakeTerminal oversizedLine = new CliHarness.FakeTerminal();
        char[] korean = new char[80];
        Arrays.fill(korean, '가');
        oversizedLine.secrets.add(new String(korean));
        assertEquals(1, cli.run(oversizedLine, "api", "rsa", "encrypt", "--public-key", f("rsa-public.pem").toString(), "--lang", "en"));
        assertTrue(cli.err().contains("190") && cli.out().isEmpty(), cli.err());
        assertFalse(cli.err().contains(new String(korean)));

        ok("api", "hybrid", "encrypt", "--public-key", "@rsa-public.pem", "--in", "@data", "--aad", "ctx", "--out", "@hybrid.out");
        assertArrayEquals(msg, HybridEncryption.decrypt(privateKey, Encoding.BASE64.decode(text("hybrid.out")), Bytes.utf8("ctx")));
        input("hybrid.back", Encoding.BASE64.encode(HybridEncryption.encrypt(publicKey, msg)));
        ok("api", "hybrid", "decrypt", "--private-key", "@rsa-private.pem", "--in", "@hybrid.back", "--out", "@hybrid.clear");
        assertEquals(1, run("api", "hybrid", "decrypt", "--private-key", "@rsa-private.pem", "--in", "@hybrid.back",
                "--aad", "wrong", "--out", "@never"));
        assertFalse(Files.exists(f("never")));
        for (String type : new String[] {"rsa", "ec"}) {
            String alg = type.equals("rsa") ? "rsa-sha256" : "ecdsa-sha256";
            SignatureAlgorithm sa = type.equals("rsa") ? SignatureAlgorithm.RSA_SHA256 : SignatureAlgorithm.ECDSA_P256_SHA256;
            ok("api", "signature", "sign", "--algorithm", alg, "--private-key", "@" + type + "-private.pem",
                    "--in", "@data", "--out", "@" + type + ".sig");
            assertTrue(Signatures.verify(sa, PemKeys.readPublicKeyFile(f(type + "-public.pem")), msg,
                    Encoding.BASE64.decode(text(type + ".sig"))));
            String signed = Encoding.BASE64.encode(Signatures.sign(sa, PemKeys.readPrivateKeyFile(f(type + "-private.pem")), msg));
            input(type + ".api.sig", signed);
            ok("api", "signature", "verify", "--algorithm", alg, "--public-key", "@" + type + "-public.pem", "--in", "@data",
                    "--signature-file", "@" + type + ".api.sig");
        }
        ok("api", "keyconvert", "--type", "private", "--format", "der", "--in", "@rsa-private.pem", "--out", "@rsa.der");
        assertArrayEquals(privateKey.getEncoded(), Files.readAllBytes(f("rsa.der")));
        ok("api", "keyconvert", "--type", "private", "--format", "pem", "--in", "@rsa.der", "--out", "@round.pem");
        assertArrayEquals(privateKey.getEncoded(), PemKeys.readPrivateKeyFile(f("round.pem")).getEncoded());
        assertEquals(1, run("api", "keyconvert", "--type", "public", "--format", "der", "--in", "@rsa.der", "--out", "@bad.der"));
    }

    @Test
    void utilitiesReusePublicFormatsAndReturnJudgments() throws Exception {
        byte[] original = {(byte) 0xef, (byte) 0xbb, (byte) 0xbf, 'x', '\r', '\n', (byte) 0xff};
        input("data", "temporary");
        Files.write(f("data"), original);
        for (Encoding enc : Encoding.values()) {
            String fmt = enc.name().toLowerCase(java.util.Locale.ROOT).replace("_", "");
            ok("api", "encode", "--encoding", fmt, "--in", "@data", "--out", "@enc" + fmt);
            assertEquals(enc.encode(original), text("enc" + fmt));
            ok("api", "decode", "--encoding", fmt, "--in", "@enc" + fmt, "--out", "@dec" + fmt);
            assertArrayEquals(original, Files.readAllBytes(f("dec" + fmt)));
        }
        byte[] limit = new byte[ApiInput.MIB];
        limit[0] = (byte) 0xff;
        limit[limit.length - 1] = '\n';
        Files.write(f("limit.bin"), limit);
        ok("api", "encode", "--encoding", "hex", "--in", "@limit.bin", "--out", "@limit.hex");
        ok("api", "decode", "--encoding", "hex", "--in", "@limit.hex", "--out", "@limit-roundtrip.bin");
        assertArrayEquals(limit, Files.readAllBytes(f("limit-roundtrip.bin")));
        input("malformed.b64", "???");
        assertEquals(1, run("api", "decode", "--in", "@malformed.b64", "--out", "@invalid"));
        assertFalse(Files.exists(f("invalid")));
        ok("api", "hash", "generate", "--in", "@data", "--out", "@hash");
        assertEquals(Digests.sha256Hex(original), text("hash"));
        ok("api", "hash", "verify", "--in", "@data", "--expected-file", "@hash");
        input("utf8.txt", "digest text");
        ok("api", "hash", "generate", "--in", "@utf8.txt");
        assertEquals(Digests.sha256Hex(Bytes.utf8("digest text")), cli.out().trim());
        for (String alg : new String[] {"sha256", "sha512"}) {
            keygen("hmac", "key" + alg, "--algorithm", alg);
            ok("api", "hmac", "sign", "--algorithm", alg, "--key-file", "@key" + alg, "--in", "@data", "--out", "@mac" + alg);
            Hmac hmac = Hmac.of(alg.equals("sha256") ? HmacAlgorithm.SHA256 : HmacAlgorithm.SHA512,
                    Encoding.BASE64.decode(text("key" + alg)));
            assertEquals(hmac.sign(original, Encoding.HEX), text("mac" + alg));
            ok("api", "hmac", "verify", "--algorithm", alg, "--key-file", "@key" + alg, "--in", "@data", "--expected-file", "@mac" + alg);
        }
        input("mismatch", Encoding.HEX.encode(new byte[32]));
        assertEquals(1, run("api", "hash", "verify", "--in", "@data", "--expected-file", "@mismatch"));
        assertEquals("FAIL", cli.out().trim());
        assertEquals(1, run("api", "hmac", "verify", "--key-file", "@keysha256", "--in", "@data", "--expected-file", "@mismatch"));
        assertEquals("FAIL", cli.out().trim());
        assertEquals(1, run("api", "random", "bytes", "--length", "65537", "--out", "@over-limit"));
        assertFalse(Files.exists(f("over-limit")));
        ok("api", "random", "bytes", "--length", "16", "--encoding", "hex", "--out", "@salt");
        assertEquals(16, Encoding.HEX.decode(text("salt")).length);
        ok("api", "random", "token", "--out", "@token");
        assertEquals(32, Encoding.BASE64_URL.decode(text("token")).length);
        ok("api", "random", "string", "--alphabet", "digits", "--length", "6", "--prefix", "R-", "--out", "@code");
        assertTrue(text("code").matches("R-[0-9]{6}"));
        ok("api", "random", "nonce");
        assertEquals(16, Encoding.BASE64_URL.decode(cli.out().trim()).length);
        ok("api", "random", "uuid");
        assertEquals(4, java.util.UUID.fromString(cli.out().trim()).version());
        input("pass", "simple fixture password");
        ok("api", "password", "hash", "--iterations", "100000", "--password-file", "@pass", "--out", "@stored");
        assertTrue(Passwords.verify("simple fixture password".toCharArray(), text("stored")));
        ok("api", "password", "verify", "--password-file", "@pass", "--in", "@stored");
        ok("api", "password", "needs-rehash", "--in", "@stored");
        assertEquals("true", cli.out().trim());
        ok("api", "kdf", "pbkdf2", "--pass-file", "@pass", "--iterations", "100000", "--salt-file", "@salt", "--out", "@derived");
        assertArrayEquals(Pbkdf2.deriveKey(Pbkdf2Algorithm.SHA256, "simple fixture password".toCharArray(),
                Encoding.HEX.decode(text("salt")), 100000, 32), Encoding.BASE64.decode(text("derived")));
        ok("api", "kdf", "hkdf", "--key-file", "@keysha256", "--info", "trial", "--out", "@hkdf");
        assertArrayEquals(Hkdf.derive(HmacAlgorithm.SHA256, Encoding.BASE64.decode(text("keysha256")), null, "trial", 32),
                Encoding.BASE64.decode(text("hkdf")));
        assertFalse(Files.exists(f("bad")));
    }

    @Test
    void claimsOtpAndRequestAuthenticationRoundTrip() throws Exception {
        keygen("hmac", "jwt.key");
        keygen("rsa", "rsa", "--bits", "2048");
        keygen("ec", "ec");
        input("claims.json", "{\"department\":\"dev\",\"roles\":[\"read\"],\"number\":10,\"active\":true}");
        for (String alg : new String[] {"hs256", "rs256", "es256"}) {
            String type = alg.equals("rs256") ? "rsa" : "ec";
            String[] write = alg.equals("hs256") ? new String[]{"--key-file", "@jwt.key"}
                    : new String[]{"--private-key", "@" + type + "-private.pem"};
            String[] trust = alg.equals("hs256") ? new String[]{"--key-file", "@jwt.key"}
                    : new String[]{"--public-key", "@" + type + "-public.pem"};
            ok("api", "jwt", "create", "--algorithm", alg, write[0], write[1], "--issuer", "test", "--audience", "svc", "--subject", "user1",
                    "--claims-file", "@claims.json", "--kid", "kid1", "--out", "@" + alg);
            assertEquals("dev", Jwt.parseUnverified(text(alg)).claims().getString("department"));
            ok("api", "jwt", "verify", "--algorithm", alg, trust[0], trust[1], "--issuer", "test", "--audience", "svc",
                    "--kid", "kid1", "--in", "@" + alg);
            assertEquals(1, run("api", "jwt", "verify", "--algorithm", alg, trust[0], trust[1], "--issuer", "wrong",
                    "--audience", "svc", "--kid", "kid1", "--in", "@" + alg));
        }
        input("expected.json", "{\"department\":\"dev\"}");
        ok("api", "jwt", "verify", "--algorithm", "hs256", "--key-file", "@jwt.key", "--kid", "kid1", "--issuer", "test",
                "--any-audience", "--subject", "user1", "--require-claims", "sub department",
                "--require-claim-values-file", "@expected.json", "--in", "@hs256");
        assertEquals(1, run("api", "jwt", "verify", "--algorithm", "hs256", "--key-file", "@jwt.key", "--kid", "kid1",
                "--issuer", "test", "--in", "@hs256"));
        assertEquals(1, run("api", "jwt", "verify", "--algorithm", "hs256", "--key-file", "@jwt.key", "--kid", "kid1",
                "--issuer", "test", "--audience", "svc", "--any-audience", "--in", "@hs256"));
        input("expected.json", "{\"department\":42}");
        assertEquals(1, run("api", "jwt", "verify", "--algorithm", "hs256", "--key-file", "@jwt.key", "--kid", "kid1",
                "--issuer", "test", "--any-audience", "--require-claim-values-file", "@expected.json", "--in", "@hs256"));
        input("expected.json", "{\"sub\":\"user1\"}");
        assertEquals(1, run("api", "jwt", "verify", "--algorithm", "hs256", "--key-file", "@jwt.key", "--kid", "kid1",
                "--issuer", "test", "--any-audience", "--subject", "user1", "--require-claim-values-file", "@expected.json",
                "--in", "@hs256"));
        ok("api", "jwt", "inspect", "--in", "@hs256", "--out", "@review");
        assertTrue(text("review").contains("미검증") || text("review").contains("UNVERIFIED"));
        ok("api", "oauth", "create", "--algorithm", "rs256", "--private-key", "@rsa-private.pem", "--issuer", "test",
                "--subject", "user1", "--audience", "svc", "--client-id", "client", "--scope", "read", "--out", "@access");
        assertTrue(AccessTokenVerifier.rfc9068().issuer("test").audience("svc")
                .key(JwtKey.rs256(PemKeys.readPublicKeyFile(f("rsa-public.pem")))).build().verify(text("access")).hasScope("read"));
        ok("api", "oauth", "verify", "--algorithm", "rs256", "--public-key", "@rsa-public.pem", "--issuer", "test",
                "--audience", "svc", "--scope", "read", "--in", "@access");
        assertEquals(1, run("api", "oauth", "verify", "--algorithm", "rs256", "--public-key", "@rsa-public.pem", "--issuer", "test",
                "--audience", "svc", "--scope", "rea", "--in", "@access"));

        java.security.interfaces.RSAPublicKey rsa = (java.security.interfaces.RSAPublicKey) PemKeys.readPublicKeyFile(f("rsa-public.pem"));
        String modulus = Encoding.BASE64_URL.encode(unsigned(rsa.getModulus().toByteArray()));
        String exponent = Encoding.BASE64_URL.encode(unsigned(rsa.getPublicExponent().toByteArray()));
        input("jwks.json", "{\"keys\":[{\"kty\":\"RSA\",\"alg\":\"RS256\",\"kid\":\"kid1\",\"n\":\""
                + modulus + "\",\"e\":\"" + exponent + "\"}]}");
        assertEquals(1, run("api", "jwt", "verify", "--algorithm", "hs256", "--jwks-file", "@jwks.json",
                "--issuer", "test", "--audience", "svc", "--in", "@hs256"));
        ok("api", "jwt", "verify", "--algorithm", "rs256", "--jwks-file", "@jwks.json", "--issuer", "test",
                "--audience", "svc", "--in", "@rs256");
        assertEquals(1, run("api", "jwt", "verify", "--algorithm", "rs256", "--jwks-file", "@jwks.json",
                "--issuer", "test", "--audience", "svc", "--kid", "unregistered", "--in", "@rs256"));
        assertEquals(1, run("api", "jwt", "verify", "--algorithm", "rs256", "--jwks-file", "@jwks.json",
                "--issuer", "test", "--audience", "other", "--in", "@rs256"));
        assertEquals(1, run("api", "jwt", "verify", "--algorithm", "rs256", "--jwks-file", "@jwks.json",
                "--issuer", "test", "--audience", "svc", "--at", "2099-01-01T00:00:00Z", "--in", "@rs256"));
        String configured = Jwt.builder().type("application/vnd.example.access+jwt").issuer("test").audience("svc")
                .claim("scope", "read").expiresIn(java.time.Duration.ofMinutes(5))
                .sign(JwtKey.rs256(PemKeys.readPrivateKeyFile(f("rsa-private.pem"))).withKeyId("kid1"));
        input("configured-token", configured);
        ok("api", "oauth", "verify", "--profile", "profile", "--algorithm", "rs256", "--jwks-file", "@jwks.json",
                "--issuer", "test", "--audience", "svc", "--typ", "application/vnd.example.access+jwt",
                "--scope", "read", "--in", "@configured-token");
        assertEquals(1, run("api", "oauth", "verify", "--algorithm", "rs256", "--jwks-file", "@jwks.json",
                "--issuer", "test", "--audience", "svc", "--in", "@rs256"));
        assertEquals(1, run("api", "oauth", "verify", "--profile", "profile", "--algorithm", "rs256",
                "--jwks-file", "@jwks.json", "--issuer", "test", "--audience", "svc", "--in", "@configured-token"));
        assertEquals(1, run("api", "oauth", "create", "--profile", "profile", "--algorithm", "rs256",
                "--private-key", "@rsa-private.pem", "--issuer", "test", "--audience", "svc", "--subject", "user1",
                "--client-id", "client", "--out", "@never-profile"));
        assertFalse(Files.exists(f("never-profile")));
        keygen("otp", "otp.key");
        byte[] secret = Encoding.BASE32.decode(text("otp.key"));
        String time = "2026-11-26T00:00:00Z";
        ok("api", "otp", "generate", "--key-file", "@otp.key", "--at", time, "--out", "@totp");
        assertEquals(Totp.of(secret).generate(Instant.parse(time)), text("totp"));
        ok("api", "otp", "verify", "--key-file", "@otp.key", "--at", time, "--in", "@totp");
        ok("api", "otp", "generate", "--type", "hotp", "--key-file", "@otp.key", "--counter", "5", "--out", "@hotp");
        assertEquals(Hotp.of(secret).generate(5), text("hotp"));
        ok("api", "otp", "verify", "--type", "hotp", "--key-file", "@otp.key", "--counter", "5", "--in", "@hotp");
        ok("api", "otp", "uri", "--key-file", "@otp.key", "--issuer", "Demo", "--account", "user1", "--out", "@otp-uri");
        assertEquals(Totp.of(secret).otpauthUri("Demo", "user1"), text("otp-uri"));
        String validOtp = text("totp");
        input("invalid-otp", (validOtp.charAt(0) == '0' ? "1" : "0") + validOtp.substring(1));
        assertEquals(1, run("api", "otp", "verify", "--key-file", "@otp.key", "--at", time, "--in", "@invalid-otp"));
        assertEquals("FAIL", cli.out().trim());

        input("body", "request text");
        String epoch = Long.toString(Instant.parse(time).getEpochSecond());
        ok("api", "request-auth", "sign", "--key-file", "@jwt.key", "--in", "@body", "--at", epoch, "--out", "@request.json");
        ok("api", "request-auth", "verify", "--key-file", "@jwt.key", "--in", "@body", "--at", epoch,
                "--auth-file", "@request.json");
        CliHarness.FakeTerminal requestConsole = new CliHarness.FakeTerminal();
        assertEquals(0, cli.run(requestConsole, "api", "req-auth", "sign", "--key-file", f("jwt.key").toString(),
                "--in", f("body").toString(), "--at", epoch, "--lang", "en"), cli.err());
        assertTrue(cli.out().contains("\n"), cli.out());
        java.util.Map<?, ?> displayed = (java.util.Map<?, ?>) io.javacryptokit.json.StrictJson.parse(cli.out());
        assertEquals(epoch, displayed.get("timestamp"));
        assertTrue(displayed.containsKey("nonce") && displayed.containsKey("mac"));
        RequestAuth auth = RequestAuth.of(Hmac.of(HmacAlgorithm.SHA256, Encoding.BASE64.decode(text("jwt.key"))),
                RequestAuth.DEFAULT_MAX_SKEW, java.time.Clock.fixed(Instant.parse(time), java.time.ZoneOffset.UTC));
        byte[] body = Files.readAllBytes(f("body"));
        java.util.Map<?, ?> record = (java.util.Map<?, ?>) io.javacryptokit.json.StrictJson.parse(text("request.json"));
        assertEquals(epoch, record.get("timestamp"));
        assertEquals(RequestAuth.Result.VALID, auth.verify(body, epoch, (String) record.get("nonce"), (String) record.get("mac")));
        RequestAuth.Signed signed = auth.sign(body);
        ok("api", "request-auth", "verify", "--key-file", "@jwt.key", "--in", "@body", "--at", epoch,
                "--timestamp", signed.timestamp(), "--nonce", signed.nonce(), "--mac", signed.mac());
        assertEquals(1, run("api", "request-auth", "sign", "--key-file", "@jwt.key", "--in", "@body", "--at", epoch,
                "--nonce", signed.nonce(), "--out", "@fixed-nonce"));
        assertFalse(Files.exists(f("fixed-nonce")));
        assertEquals(1, run("api", "request-auth", "verify", "--key-file", "@jwt.key", "--in", "@body",
                "--at", Long.toString(Long.parseLong(epoch) + 901), "--auth-file", "@request.json"));
        assertTrue(cli.err().contains("TIMESTAMP_OUT_OF_RANGE"));
        input("invalid-request.json", "{\"timestamp\":\"0\",\"nonce\":\"x\",\"mac\":\"x\"}");
        assertEquals(1, run("api", "request-auth", "verify", "--key-file", "@jwt.key", "--in", "@body",
                "--at", epoch, "--auth-file", "@invalid-request.json"));
        assertTrue(cli.err().contains("MALFORMED"), cli.err());
        input("body", "changed");
        assertEquals(1, run("api", "request-auth", "verify", "--key-file", "@jwt.key", "--in", "@body", "--at", epoch,
                "--auth-file", "@request.json"));
        assertTrue(cli.err().contains("BAD_MAC"), cli.err());

    }

    private static byte[] unsigned(byte[] bytes) {
        return bytes[0] == 0 ? Arrays.copyOfRange(bytes, 1, bytes.length) : bytes;
    }

    @Test
    void certificateFieldsMatchApi() throws Exception {
        TestKeytool.caAndServer(dir, "dns:local.example");
        CertificateInfo info = Certificates.info(Certificates.readFile(f("ca.pem")));
        ok("api", "certificate", "info", "--in", "@ca.pem", "--out", "@cert-info");
        String displayed = text("cert-info");
        assertTrue(displayed.contains(info.sha256Fingerprint()));
        assertTrue(displayed.contains(info.notAfter().toString()));
        assertTrue(displayed.contains(info.subject()));
    }
}

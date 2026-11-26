package io.javacryptokit.cli;

import io.javacryptokit.i18n.Messages;
import io.javacryptokit.key.SecretFiles;
import io.javacryptokit.json.StrictJson;
import io.javacryptokit.security.Bytes;
import io.javacryptokit.security.Encoding;
import java.io.IOException;
import java.io.InputStream;
import java.io.PrintStream;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.Files;
import java.nio.file.InvalidPathException;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.attribute.PosixFilePermissions;
import java.time.Duration;
import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

/** Input and output shared by independent API commands. Call only after the central authentication gate. */
final class ApiInput implements AutoCloseable {
    static final int MIB = 1024 * 1024;
    static final int KEY_LIMIT = 64 * 1024;
    final CryptoCli.TerminalProvider terminals;
    final PrintStream out;
    final PrintStream err;
    private final CliCommands.Parsed args;
    private final List<byte[]> secrets = new ArrayList<>();
    private final List<char[]> passwords = new ArrayList<>();
    private final List<Path> publishedFiles = new ArrayList<>(2);

    ApiInput(CliCommands.Parsed args, CryptoCli.TerminalProvider terminals, PrintStream out, PrintStream err) {
        this.args = args;
        this.terminals = terminals;
        this.out = out;
        this.err = err;
    }

    static void precheck(CliCommands.Parsed args) throws CryptoCli.CliException {
        if (args.flag("--show") && args.value("--out") != null) {
            throw problem("api.err.exclusive", "--show", "--out");
        }
        for (String option : args.values.keySet()) {
            if (option.equals("--in") || option.equals("--out") || option.endsWith("-file")
                    || option.equals("--public-key") || option.equals("--private-key")) {
                String value = args.value(option);
                if (value.trim().isEmpty()) throw problem("api.err.required", option);
                path(option.substring(2), value);
            }
        }
    }

    String value(String opt) {
        return args.value("--" + opt);
    }

    String value(String opt, String fallback) {
        String value = value(opt);
        return value == null ? fallback : value;
    }

    boolean flag(String opt) {
        return args.flag("--" + opt);
    }

    String choice(String opt, String fallback, String... allowed) throws CryptoCli.CliException {
        String result = value(opt, fallback);
        if (result == null) {
            result = ask(opt, Messages.get("api.prompt.choice", label(opt, "value"), String.join(" / ", allowed)));
        }
        for (String item : allowed) if (item.equals(result)) return item;
        throw problem("api.err.choice", "--" + opt, String.join(", ", allowed));
    }

    String required(String opt) throws CryptoCli.CliException {
        String value = value(opt);
        if (value == null || value.trim().isEmpty()) throw problem("api.err.required", "--" + opt);
        return value;
    }

    String ask(String opt) throws CryptoCli.CliException {
        return ask(opt, label(opt, "value") + ":");
    }

    private String ask(String opt, String prompt) throws CryptoCli.CliException {
        String value = value(opt);
        if (value == null) value = promptTerminal(opt).readLine(prompt + " ");
        if (value == null || value.trim().isEmpty()) throw problem("api.err.required", "--" + opt);
        return value;
    }

    private CryptoCli.Terminal promptTerminal(String opt) throws CryptoCli.CliException {
        CryptoCli.Terminal terminal = CryptoCli.interactive(terminals);
        if (terminal == null) throw problem("api.err.required", "--" + opt);
        return terminal;
    }

    private String label(String opt, String mode) {
        String contextual = "api.prompt." + args.spec.topic + "." + opt;
        if (Messages.has(Messages.current(), contextual)) return Messages.get(contextual);
        String common = "api.prompt." + mode + "." + opt;
        return Messages.has(Messages.current(), common) ? Messages.get(common) : Messages.get("api.prompt.option", "--" + opt);
    }

    private String secretPrompt(String opt) {
        if ("key-file".equals(opt)) {
            String format = args.spec.name.startsWith("api otp ") ? "base32" : value("key-encoding", "base64");
            String keyLabel = args.spec.name.startsWith("api aes ") ? "AES Key" : Messages.get("api.prompt.secret.key-file");
            String encoding = Messages.get("api.prompt.encoding." + format);
            return Messages.get("api.prompt.key", keyLabel, encoding);
        }
        return Messages.get("api.prompt.hidden", label(opt, "secret"));
    }

    void excludes(String... options) throws CryptoCli.CliException {
        for (String option : options) {
            if (value(option) != null || flag(option)) throw problem("api.err.incompatible", "--" + option);
        }
    }

    void exclusive(String left, String right) throws CryptoCli.CliException {
        if (value(left) != null && value(right) != null) throw problem("api.err.exclusive", "--" + left, "--" + right);
    }

    long number(String opt, Long fallback, long min, long max) throws CryptoCli.CliException {
        String value = value(opt);
        if (value == null) {
            if (fallback != null) return fallback;
            value = ask(opt, Messages.get("api.prompt.range", label(opt, "value"), min, max));
        }
        try {
            if (value.matches("[0-9]{1,19}")) {
                long parsed = Long.parseLong(value);
                if (parsed >= min && parsed <= max) return parsed;
            }
        } catch (NumberFormatException ignored) {
            // No option value goes into the diagnostic.
        }
        throw problem("api.err.number", "--" + opt, min, max);
    }

    int integer(String opt, int fallback, int min, int max) throws CryptoCli.CliException {
        return (int) number(opt, (long) fallback, min, max);
    }

    Duration seconds(String opt, int fallback, int lower, int upper) throws CryptoCli.CliException {
        return Duration.ofSeconds(integer(opt, fallback, lower, upper));
    }

    Instant instant(String opt, Instant fallback) throws CryptoCli.CliException {
        String value = value(opt);
        if (value == null) return fallback;
        try {
            return Instant.parse(value);
        } catch (DateTimeParseException e) {
            throw problem("api.err.time", "--" + opt);
        }
    }

    Encoding encoding(String opt, String fallback) throws CryptoCli.CliException {
        switch (choice(opt, fallback, "hex", "base64", "base64url", "base32")) {
            case "hex": return Encoding.HEX;
            case "base64": return Encoding.BASE64;
            case "base32": return Encoding.BASE32;
            default: return Encoding.BASE64_URL;
        }
    }

    Path path(String opt) throws CryptoCli.CliException {
        return path(opt, ask(opt, label(opt, "path") + ":"));
    }

    private static Path path(String opt, String path) throws CryptoCli.CliException {
        try {
            return Paths.get(path).toAbsolutePath().normalize();
        } catch (InvalidPathException e) {
            throw problem("cli.err.path", "--" + opt);
        }
    }

    byte[] data(String opt, int max, boolean hidden) throws CryptoCli.CliException {
        return data(opt, max, hidden, "api.err.limit", "--" + opt, max);
    }

    byte[] data(String opt, int max, boolean hidden, String limitKey, Object... limitArgs)
            throws CryptoCli.CliException {
        byte[] bytes;
        if (value(opt) != null) {
            bytes = file(opt, max, hidden, limitKey, limitArgs);
        } else if (hidden) {
            char[] chars = readSecret(opt, max, limitKey, limitArgs);
            try {
                ByteBuffer encoded = StandardCharsets.UTF_8.newEncoder().encode(CharBuffer.wrap(chars));
                try {
                    if (encoded.remaining() > max) throw problem(limitKey, limitArgs);
                    bytes = new byte[encoded.remaining()];
                    encoded.get(bytes);
                } finally {
                    Arrays.fill(encoded.array(), (byte) 0);
                }
            } catch (CharacterCodingException e) {
                throw invalid("api.err.utf8", "--" + opt);
            } finally {
                Arrays.fill(chars, '\0');
            }
        } else {
            String line = promptTerminal(opt).readLine(label(opt, "plain") + ": ");
            if (line == null) throw problem("api.err.required", "--" + opt);
            bytes = utf8(line, opt, max, limitKey, limitArgs);
        }
        return hidden ? keep(bytes) : bytes;
    }

    String text(String opt, int limit, boolean secret) throws CryptoCli.CliException {
        return text(opt, limit, secret, "api.err.limit", "--" + opt, limit);
    }

    String text(String opt, int limit, boolean secret, String limitKey, Object... limitArgs)
            throws CryptoCli.CliException {
        if (value(opt) == null) {
            if (!secret) {
                String value = ask(opt, label(opt, "plain") + ":");
                utf8(value, opt, limit, limitKey, limitArgs);
                return value;
            }
            char[] chars = readSecret(opt, limit, limitKey, limitArgs);
            try {
                String value = new String(chars);
                Arrays.fill(utf8(value, opt, limit, limitKey, limitArgs), (byte) 0);
                return value;
            } finally {
                Arrays.fill(chars, '\0');
            }
        }
        byte[] bytes = file(opt, limit, secret, limitKey, limitArgs);
        try {
            return oneLine(Bytes.utf8String(bytes));
        } catch (IllegalArgumentException e) {
            throw invalid("api.err.utf8", "--" + opt);
        } finally {
            if (secret) Arrays.fill(bytes, (byte) 0);
        }
    }

    private static byte[] utf8(String value, String opt, int max, String limitKey, Object... limitArgs)
            throws CryptoCli.CliException {
        if (value.length() > max) throw problem(limitKey, limitArgs);
        byte[] bytes;
        try {
            bytes = Bytes.utf8(value);
        } catch (IllegalArgumentException e) {
            throw invalid("api.err.utf8", "--" + opt);
        }
        if (bytes.length > max) {
            Arrays.fill(bytes, (byte) 0);
            throw problem(limitKey, limitArgs);
        }
        return bytes;
    }

    char[] password(String opt) throws CryptoCli.CliException {
        char[] chars;
        if (value(opt) == null) {
            chars = readSecret(opt, KEY_LIMIT, "api.err.limit", "--" + opt, KEY_LIMIT);
            try {
                ByteBuffer bytes = StandardCharsets.UTF_8.newEncoder().encode(CharBuffer.wrap(chars));
                int length = bytes.remaining();
                Arrays.fill(bytes.array(), (byte) 0);
                if (length > KEY_LIMIT) throw problem("api.err.limit", "--" + opt, KEY_LIMIT);
            } catch (CharacterCodingException | CryptoCli.CliException e) {
                Arrays.fill(chars, '\0');
                if (e instanceof CryptoCli.CliException) throw (CryptoCli.CliException) e;
                throw invalid("api.err.utf8", "--" + opt);
            }
        } else {
            chars = text(opt, KEY_LIMIT, true).toCharArray();
        }
        passwords.add(chars);
        return chars;
    }

    private char[] readSecret(String opt, int max, String limitKey, Object... limitArgs)
            throws CryptoCli.CliException {
        char[] chars = promptTerminal(opt).readSecret(secretPrompt(opt) + " ");
        if (chars == null) throw problem("api.err.required", "--" + opt);
        if (chars.length > max) {
            Arrays.fill(chars, '\0');
            throw problem(limitKey, limitArgs);
        }
        return chars;
    }

    byte[] key(String opt, String defaultEncoding) throws CryptoCli.CliException {
        return keep(decoded(opt, KEY_LIMIT, true, encoding("key-encoding", defaultEncoding)));
    }

    byte[] decoded(String opt, int max, boolean secret, Encoding encoding) throws CryptoCli.CliException {
        return decode(opt, text(opt, max, secret), encoding);
    }

    private static byte[] decode(String opt, String value, Encoding encoding) throws CryptoCli.CliException {
        try {
            return encoding.decode(value);
        } catch (IllegalArgumentException e) {
            throw invalid("api.err.encoding", "--" + opt, encoding.name().replace("_", ""));
        }
    }

    Object json(String opt, int max, StrictJson.Limits limits) throws CryptoCli.CliException {
        String input = text(opt, max, true);
        try {
            return StrictJson.parse(input, limits);
        } catch (IllegalArgumentException e) {
            throw invalid("api.err.json", "--" + opt);
        }
    }

    byte[] associated(String opt, int limit) throws IOException, CryptoCli.CliException {
        exclusive(opt, opt + "-file");
        if (value(opt + "-file") != null) return file(opt + "-file", limit, false, "api.err.limit", "--" + opt + "-file", limit);
        byte[] bytes = Bytes.utf8(value(opt, ""));
        if (bytes.length > limit) throw problem("api.err.limit", "--" + opt, limit);
        return bytes;
    }

    byte[] salt() throws CryptoCli.CliException {
        return salt(0, 0);
    }

    byte[] salt(int min, int max) throws CryptoCli.CliException {
        exclusive("salt", "salt-file");
        byte[] result;
        if (value("salt-file") != null) {
            result = decoded("salt-file", KEY_LIMIT, false, Encoding.HEX);
        } else {
            String value = value("salt");
            if (value == null && min > 0) value = ask("salt", Messages.get(min == max
                    ? "api.prompt.saltExact" : "api.prompt.saltRange", min, max));
            if (value == null) return null;
            result = decode("salt", value, Encoding.HEX);
        }
        if (min > 0 && (result.length < min || result.length > max)) {
            throw invalid(min == max ? "api.err.directSalt" : "api.err.saltBytes", min, max);
        }
        return result;
    }

    Path protectedPath(String opt) throws CryptoCli.CliException {
        Path file = path(opt);
        if (!Files.isRegularFile(file)) throw problem("api.err.file", "--" + opt);
        AdminPassword.checkPermissions(file, "USAGE", "--" + opt);
        return file;
    }

    private byte[] file(String opt, int max, boolean secret, String limitKey, Object... limitArgs)
            throws CryptoCli.CliException {
        Path file = secret ? protectedPath(opt) : path(opt);
        if (!Files.isRegularFile(file)) throw problem("api.err.file", "--" + opt);
        byte[] buffer = null;
        try {
            long size = Files.size(file);
            if (size > max) throw problem(limitKey, limitArgs);
            try (InputStream in = Files.newInputStream(file)) {
                buffer = new byte[(int) size];
                int total = 0;
                while (true) {
                    while (total < buffer.length) {
                        int count = in.read(buffer, total, buffer.length - total);
                        if (count < 0) return Arrays.copyOf(buffer, total);
                        total += count;
                    }
                    int next = in.read();
                    if (next < 0) break;
                    if (total == max) throw problem(limitKey, limitArgs);
                    byte[] larger = Arrays.copyOf(buffer, Math.min(max, Math.max(8192, total * 2)));
                    if (secret) Arrays.fill(buffer, (byte) 0);
                    buffer = larger;
                    buffer[total++] = (byte) next;
                }
            }
            byte[] result = buffer;
            buffer = null;
            return result;
        } catch (IOException e) {
            throw new CryptoCli.CliException("IO_ERROR", Messages.get("api.err.read", "--" + opt));
        } finally {
            if (secret && buffer != null) Arrays.fill(buffer, (byte) 0);
        }
    }

    byte[] keep(byte[] bytes) {
        secrets.add(bytes);
        return bytes;
    }

    private static String oneLine(String text) {
        if (text.startsWith("\uFEFF")) text = text.substring(1);
        if (text.endsWith("\r\n")) return text.substring(0, text.length() - 2);
        if (text.endsWith("\n")) return text.substring(0, text.length() - 1);
        return text;
    }

    /** Validate the destination before collecting secrets or doing expensive work. */
    Path target(boolean secret) throws CryptoCli.CliException {
        String target = value("out");
        if (flag("show")) {
            String confirmation = terminals.open().readLine(Messages.get("api.show.prompt") + " ");
            if (!"SHOW".equals(confirmation)) throw problem("api.err.cancel");
        } else if (target == null && secret) {
            target = ask("out");
        }
        return target == null ? null : newTarget(path("out", target));
    }

    static Path newTarget(Path target) throws CryptoCli.CliException {
        if (target.getParent() == null || !Files.isDirectory(target.getParent())) throw problem("api.err.outputDir");
        if (Files.exists(target, LinkOption.NOFOLLOW_LINKS)) throw problem("api.err.outputExists");
        return target;
    }

    void result(Path target, String text, boolean secret) throws IOException, CryptoCli.CliException {
        if (target == null) {
            if (secret) {
                char[] display = text.toCharArray();
                try {
                    terminals.open().printSecret(display);
                } finally {
                    Arrays.fill(display, '\0');
                }
            } else {
                out.println(text);
            }
        } else {
            byte[] bytes = Bytes.utf8(text + "\n");
            try {
                publish(target, bytes);
            } finally {
                if (secret) Arrays.fill(bytes, (byte) 0);
            }
        }
    }

    /** Keep files and redirected output compact; lay out multi-field results at a terminal. */
    void jsonResult(Path target, Map<String, ?> values, boolean secret) throws IOException, CryptoCli.CliException {
        if (target != null || (!flag("show") && CryptoCli.interactive(terminals) == null)) {
            result(target, StrictJson.write(values), secret);
            return;
        }
        StringBuilder display = new StringBuilder(secret ? "" : "{");
        boolean first = true;
        for (Map.Entry<String, ?> item : values.entrySet()) {
            if (!first && !secret) display.append(',');
            if (!first || !secret) display.append('\n');
            String label = secret ? item.getKey() : "  " + StrictJson.write(item.getKey());
            display.append(CliHelp.pad(label, 15)).append(" : ").append(StrictJson.write(item.getValue()));
            first = false;
        }
        if (!secret) display.append("\n}");
        result(target, display.toString(), secret);
    }

    void binary(Path target, byte[] data, boolean secret) throws IOException, CryptoCli.CliException {
        if (target != null) {
            publish(target, data);
        } else {
            String text;
            try {
                text = Bytes.utf8String(data);
            } catch (IllegalArgumentException e) {
                throw problem("api.err.binary");
            }
            if (secret) result(null, text, true);
            else out.print(text);
        }
    }

    /** Publish a completed file without replacement. The staging name has the same privileges as the final file. */
    void publish(Path target, byte[] data) throws IOException, CryptoCli.CliException {
        Path parent = target.getParent();
        boolean posix = parent.getFileSystem().supportedFileAttributeViews().contains("posix");
        Path staged = posix
                ? Files.createTempFile(parent, ".jck-api-", ".tmp",
                        PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------")))
                : Files.createTempFile(parent, ".jck-api-", ".tmp");
        boolean published = false;
        try {
            Files.write(staged, data);
            try {
                Files.createLink(target, staged);
            } catch (FileAlreadyExistsException e) {
                throw problem("api.err.outputExists");
            } catch (IOException | UnsupportedOperationException e) {
                throw new CryptoCli.CliException("IO_ERROR", Messages.get("api.err.publish"));
            }
            published = true;
        } finally {
            try {
                Files.deleteIfExists(staged);
            } catch (IOException | SecurityException e) {
                String tempName = SecretFiles.fileName(staged);
                if (published) {
                    throw new CryptoCli.CliException("IO_ERROR",
                            Messages.get("file.err.publishedTempLeft", SecretFiles.fileName(target), tempName));
                }
                err.println(Messages.error("IO_ERROR", Messages.get("file.err.tempLeft", tempName)));
            }
        }
        publishedFiles.add(target);
    }

    void printReceipt() {
        if (publishedFiles.isEmpty() || CryptoCli.interactive(terminals) == null) return;
        boolean pair = publishedFiles.size() == 2;
        String title = "api.result." + args.spec.topic;
        if (pair) title = "api.result.keyPair";
        else if (!Messages.has(Messages.current(), title)) title = "api.result.saved";
        err.println("[OK] " + Messages.get(title));
        err.println(Messages.get(pair ? "api.result.publicFile" : "api.result.file", SecretFiles.fileName(publishedFiles.get(0))));
        if (pair) err.println(Messages.get("api.result.privateFile", SecretFiles.fileName(publishedFiles.get(1))));
    }


    int verify(boolean ok) {
        out.println(ok ? "OK" : "FAIL");
        return ok ? 0 : 1;
    }

    static CryptoCli.CliException invalid(String key, Object... args) {
        return new CryptoCli.CliException("INVALID_INPUT", Messages.get(key, args));
    }

    static CryptoCli.CliException problem(String key, Object... args) {
        return new CryptoCli.CliException(Messages.get(key, args));
    }

    @Override
    public void close() {
        for (byte[] key : secrets) Arrays.fill(key, (byte) 0);
        for (char[] password : passwords) Arrays.fill(password, '\0');
    }
}

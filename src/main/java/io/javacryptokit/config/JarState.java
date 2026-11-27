package io.javacryptokit.config;

import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.EOFException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.channels.FileLock;
import java.nio.channels.OverlappingFileLockException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.PosixFileAttributeView;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Set;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.jar.JarOutputStream;
import java.util.zip.ZipEntry;

/** Internal mutable JAR state. Only local ZIP extra-field payload bytes are writable at runtime. */
public final class JarState {
    public static final String ATTRIBUTE = "JCK-State-Format";
    private static final String VERSION = "1";
    private static final String PREFIX = "META-INF/jck-state/";
    private static final int EXTRA_ID = 0x4a43;
    private static final int SEGMENT = 60 * 1024;
    private static final int SEGMENTS_PER_BANK = 39;
    private static final int BANK_BYTES = SEGMENT * SEGMENTS_PER_BANK;
    private static final int SEGMENTS = 1 + SEGMENTS_PER_BANK * 2;
    private static final int DIGEST_BYTES = 32;
    private static final int FRAME_HEADER = DIGEST_BYTES + 12;
    private static final long LOCK_POSITION = Long.MAX_VALUE - 16;
    private static final byte[] ZERO = new byte[SEGMENT];

    private JarState() { }

    /** The three resources selected by the commit byte, or absent for a pristine JAR. */
    public static final class State {
        public final byte[] settings;
        public final byte[] history;
        public final byte[] admin;

        private State(byte[] settings, byte[] history, byte[] admin) {
            this.settings = settings;
            this.history = history;
            this.admin = admin;
        }
    }

    /** An I/O failure after the published state became visible. */
    public static final class PublicationException extends IOException {
        private static final long serialVersionUID = 1L;

        private PublicationException(IOException cause) {
            super("state publication interrupted", cause);
        }
    }

    /** Used at assembly time only. The copied ZIP entries keep their bytes and CRCs. */
    public static void reserve(Path input, Path output) throws IOException {
        try (JarFile jar = new JarFile(input.toFile(), false);
             JarOutputStream out = new JarOutputStream(Files.newOutputStream(output))) {
            JarEntry manifest = jar.getJarEntry(JarFile.MANIFEST_NAME);
            if (manifest == null) throw new IOException("missing manifest");
            copy(jar, manifest, out);
            reserveEntries(out);
            java.util.Enumeration<JarEntry> entries = jar.entries();
            while (entries.hasMoreElements()) {
                JarEntry entry = entries.nextElement();
                if (!JarFile.MANIFEST_NAME.equals(entry.getName())) copy(jar, entry, out);
            }
        }
    }

    /** Shared by the build and test fixture producers, never used by CLI mutation. */
    public static void reserveEntries(JarOutputStream out) throws IOException {
        for (int i = 0; i < SEGMENTS; i++) {
            int length = segmentLength(i);
            JarEntry carrier = new JarEntry(PREFIX + i);
            carrier.setTime(0);
            carrier.setMethod(ZipEntry.STORED);
            carrier.setSize(0);
            carrier.setCrc(0);
            byte[] extra = new byte[length + 4];
            extra[0] = (byte) EXTRA_ID;
            extra[1] = (byte) (EXTRA_ID >>> 8);
            extra[2] = (byte) length;
            extra[3] = (byte) (length >>> 8);
            carrier.setExtra(extra);
            out.putNextEntry(carrier);
            out.closeEntry();
        }
    }

    private static void copy(JarFile jar, JarEntry source, JarOutputStream out) throws IOException {
        JarEntry target = new JarEntry(source.getName());
        if (source.getTime() >= 0) target.setTime(source.getTime());
        out.putNextEntry(target);
        try (InputStream data = jar.getInputStream(source)) {
            byte[] buffer = new byte[8192];
            for (int n; (n = data.read(buffer)) != -1; ) out.write(buffer, 0, n);
        }
        out.closeEntry();
    }

    /** Reads the selector alone for public Help/Examples. */
    public static synchronized boolean initialized(Path path, String version) throws IOException {
        requireVersion(version);
        try (FileChannel file = FileChannel.open(path, StandardOpenOption.READ);
             FileLock ignored = lock(file, true)) {
            return active(file, layout(file)) != 0;
        }
    }

    public static synchronized State read(Path path, String version) throws IOException {
        requireVersion(version);
        try (FileChannel file = FileChannel.open(path, StandardOpenOption.READ);
             FileLock ignored = lock(file, true)) {
            long[] layout = layout(file);
            int selected = active(file, layout);
            return selected == 0 ? null : decode(readBank(file, layout, selected));
        }
    }

    /** Publishes a fully validated snapshot. The previous bank is erased after durable publication. */
    public static synchronized void update(Path path, String version, String expectedDigest,
                              byte[] settings, byte[] history, byte[] admin, boolean protect) throws IOException {
        requireVersion(version);
        if (!Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS)) throw new IOException("invalid target path");
        byte[] frame = encode(settings, history, admin);
        boolean published = false;
        try (FileChannel file = FileChannel.open(path, StandardOpenOption.READ, StandardOpenOption.WRITE,
                LinkOption.NOFOLLOW_LINKS);
             FileLock ignored = lock(file, false)) {
            long[] layout = layout(file);
            int previous = active(file, layout);
            if (previous != 0) decode(readBank(file, layout, previous));
            if (!expectedDigest.equals(fileDigest(file))) throw new IOException("state changed");
            Set<PosixFilePermission> permissions = null;
            if (protect && Files.getFileAttributeView(path, PosixFileAttributeView.class, LinkOption.NOFOLLOW_LINKS) != null) {
                permissions = Files.getPosixFilePermissions(path, LinkOption.NOFOLLOW_LINKS);
                Files.setPosixFilePermissions(path, PosixFilePermissions.fromString("rw-------"));
            }
            int next = previous == 1 ? 2 : 1;
            try {
                writeBank(file, layout, next, frame);
                file.force(true);
                if (!MessageDigest.isEqual(frame, readBank(file, layout, next))) throw new IOException("stage read-back");
                file.position(layout[0]);
                write(file, new byte[]{(byte) (next == 1 ? 0xa5 : 0x5a)}, 0, 1);
                published = true;
                file.force(true);
                // Never fall back to the obsolete state, including after a crash between these steps.
                writeBank(file, layout, next == 1 ? 2 : 1, null);
                file.force(true);
            } catch (IOException failure) {
                if (published) throw failure;
                try {
                    writeBank(file, layout, next, null);
                    file.force(true);
                } catch (IOException cleanup) {
                    // Keep setup permissions restrictive if a candidate containing secrets remains.
                    permissions = null;
                    failure.addSuppressed(cleanup);
                }
                if (permissions != null) {
                    try {
                        Files.setPosixFilePermissions(path, permissions);
                    } catch (IOException cleanup) {
                        failure.addSuppressed(cleanup);
                    }
                }
                throw failure;
            }
        } catch (IOException failure) {
            if (published) throw new PublicationException(failure);
            throw failure;
        } finally {
            Arrays.fill(frame, (byte) 0);
        }
    }

    private static FileLock lock(FileChannel file, boolean shared) throws IOException {
        try {
            FileLock result = file.tryLock(LOCK_POSITION, 1, shared);
            if (result != null) return result;
        } catch (OverlappingFileLockException e) {
            throw new IOException("state in use", e);
        }
        throw new IOException("state in use");
    }

    private static void requireVersion(String version) throws IOException {
        if (!VERSION.equals(version)) throw new IOException("unsupported state format");
    }

    private static int segmentLength(int index) {
        return index == 0 ? 1 : SEGMENT;
    }

    private static int active(FileChannel file, long[] layout) throws IOException {
        file.position(layout[0]);
        int value = bytes(file, 1)[0] & 255;
        if (value == 0) return 0;
        if (value == 0xa5) return 1;
        if (value == 0x5a) return 2;
        throw new IOException("invalid state selector");
    }

    private static byte[] readBank(FileChannel file, long[] layout, int bank) throws IOException {
        byte[] data = new byte[BANK_BYTES];
        int first = 1 + (bank - 1) * SEGMENTS_PER_BANK;
        for (int i = 0; i < SEGMENTS_PER_BANK; i++) {
            file.position(layout[first + i]);
            read(file, data, i * SEGMENT, SEGMENT);
        }
        return data;
    }

    private static void writeBank(FileChannel file, long[] layout, int bank, byte[] data) throws IOException {
        int first = 1 + (bank - 1) * SEGMENTS_PER_BANK;
        for (int i = 0; i < SEGMENTS_PER_BANK; i++) {
            file.position(layout[first + i]);
            if (data == null) write(file, ZERO, 0, ZERO.length);
            else write(file, data, i * SEGMENT, SEGMENT);
        }
    }

    private static byte[] encode(byte[] settings, byte[] history, byte[] admin) throws IOException {
        if (settings == null || history == null || admin == null ||
                FRAME_HEADER + (long) settings.length + history.length + admin.length > BANK_BYTES) {
            throw new IOException("state capacity");
        }
        byte[] frame = new byte[BANK_BYTES];
        ByteBuffer bytes = ByteBuffer.wrap(frame);
        bytes.position(DIGEST_BYTES);
        bytes.putInt(settings.length).putInt(history.length).putInt(admin.length);
        bytes.put(settings).put(history).put(admin);
        MessageDigest digest = sha256();
        digest.update(frame, DIGEST_BYTES, frame.length - DIGEST_BYTES);
        bytes.position(0);
        bytes.put(digest.digest());
        return frame;
    }

    private static State decode(byte[] data) throws IOException {
        try {
            byte[] expected = Arrays.copyOf(data, DIGEST_BYTES);
            MessageDigest digest = sha256();
            digest.update(data, DIGEST_BYTES, data.length - DIGEST_BYTES);
            if (!MessageDigest.isEqual(expected, digest.digest())) throw new IOException("invalid state digest");
            try (DataInputStream input = new DataInputStream(
                    new ByteArrayInputStream(data, DIGEST_BYTES, data.length - DIGEST_BYTES))) {
                int settingsLength = input.readInt();
                int historyLength = input.readInt();
                int adminLength = input.readInt();
                if (settingsLength < 1 || historyLength < 0 || adminLength < 0 ||
                        FRAME_HEADER + (long) settingsLength + historyLength + adminLength > data.length) {
                    throw new IOException("invalid state lengths");
                }
                byte[] settings = new byte[settingsLength];
                byte[] history = new byte[historyLength];
                byte[] admin = new byte[adminLength];
                input.readFully(settings);
                input.readFully(history);
                input.readFully(admin);
                return new State(settings, historyLength == 0 ? null : history, adminLength == 0 ? null : admin);
            }
        } finally {
            Arrays.fill(data, (byte) 0);
        }
    }

    private static long[] layout(FileChannel file) throws IOException {
        long size = file.size();
        int tailSize = (int) Math.min(size, 65557);
        byte[] tail = new byte[tailSize];
        file.position(size - tailSize);
        read(file, tail, 0, tail.length);
        for (int i = tail.length - 22; i >= 0; i--) {
            if (u32(tail, i) != 0x06054b50L || i + 22 + u16(tail, i + 20) != tail.length) continue;
            long start = u32(tail, i + 16);
            if (start + u32(tail, i + 12) != size - tailSize + i || u16(tail, i + 4) != 0 ||
                    u16(tail, i + 6) != 0 || u16(tail, i + 8) != u16(tail, i + 10)) {
                throw new IOException("unsupported ZIP directory");
            }
            return carriers(file, start, u16(tail, i + 10));
        }
        throw new IOException("missing ZIP directory");
    }

    private static long[] carriers(FileChannel file, long start, int entries) throws IOException {
        long[] offsets = new long[SEGMENTS];
        file.position(start);
        for (int i = 0; i < entries; i++) {
            byte[] header = bytes(file, 46);
            if (u32(header, 0) != 0x02014b50L) throw new IOException("invalid ZIP directory");
            String name = new String(bytes(file, u16(header, 28)), StandardCharsets.UTF_8);
            long next = file.position() + u16(header, 30) + u16(header, 32);
            if (name.startsWith(PREFIX)) {
                int index;
                try {
                    index = Integer.parseInt(name.substring(PREFIX.length()));
                } catch (NumberFormatException e) {
                    throw new IOException("invalid carrier name", e);
                }
                if (index < 0 || index >= SEGMENTS || offsets[index] != 0 || u32(header, 20) != 0 ||
                        u32(header, 24) != 0 || u16(header, 10) != 0) throw new IOException("invalid carrier");
                offsets[index] = carrier(file, name, index, u32(header, 42), start);
            }
            file.position(next);
        }
        long end = 0;
        for (int i = 0; i < offsets.length; i++) {
            if (offsets[i] <= end) throw new IOException("missing or misplaced carrier");
            end = offsets[i] + segmentLength(i) - 1;
        }
        return offsets;
    }

    private static long carrier(FileChannel file, String name, int index, long local, long central) throws IOException {
        if (local >= central) throw new IOException("invalid local carrier");
        file.position(local);
        byte[] header = bytes(file, 30);
        if (u32(header, 0) != 0x04034b50L || u16(header, 8) != 0 ||
                u32(header, 18) != 0 || u32(header, 22) != 0 ||
                !name.equals(new String(bytes(file, u16(header, 26)), StandardCharsets.UTF_8))) {
            throw new IOException("invalid local carrier");
        }
        long extraStart = file.position();
        int extraLength = u16(header, 28);
        if (extraStart + extraLength > central) throw new IOException("invalid carrier range");
        for (int i = 0; i + 4 <= extraLength; ) {
            file.position(extraStart + i);
            byte[] extra = bytes(file, 4);
            int length = u16(extra, 2);
            if (i + 4 + length > extraLength) break;
            if (u16(extra, 0) == EXTRA_ID && length == segmentLength(index)) return extraStart + i + 4;
            i += 4 + length;
        }
        throw new IOException("missing local reservation");
    }

    private static byte[] bytes(FileChannel file, int length) throws IOException {
        byte[] data = new byte[length];
        read(file, data, 0, data.length);
        return data;
    }

    private static void read(FileChannel file, byte[] data, int offset, int length) throws IOException {
        ByteBuffer buffer = ByteBuffer.wrap(data, offset, length);
        while (buffer.hasRemaining()) {
            if (file.read(buffer) < 0) throw new EOFException("truncated JAR state");
        }
    }

    private static void write(FileChannel file, byte[] data, int offset, int length) throws IOException {
        ByteBuffer buffer = ByteBuffer.wrap(data, offset, length);
        while (buffer.hasRemaining()) file.write(buffer);
    }

    private static int u16(byte[] data, int at) {
        return (data[at] & 255) | ((data[at + 1] & 255) << 8);
    }

    private static long u32(byte[] data, int at) {
        return u16(data, at) | ((long) u16(data, at + 2) << 16);
    }

    private static String fileDigest(FileChannel file) throws IOException {
        MessageDigest digest = sha256();
        ByteBuffer buffer = ByteBuffer.allocate(8192);
        file.position(0);
        while (file.read(buffer) != -1) {
            buffer.flip();
            digest.update(buffer);
            buffer.clear();
        }
        StringBuilder hex = new StringBuilder(64);
        for (byte b : digest.digest()) {
            hex.append(Character.forDigit((b & 255) >>> 4, 16)).append(Character.forDigit(b & 15, 16));
        }
        return hex.toString();
    }

    private static MessageDigest sha256() {
        try {
            return MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }
}

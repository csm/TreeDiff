/* 
   Copyright (C) 2014  Casey Marshall

This file is a part of Jessie.

Jessie is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 2 of the License, or (at
your option) any later version.

Jessie is distributed in the hope that it will be useful, but
WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
General Public License for more details.

You should have received a copy of the GNU General Public License
along with Jessie; if not, write to the Free Software
Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301
USA

Linking this library statically or dynamically with other modules is
making a combined work based on this library.  Thus, the terms and
conditions of the GNU General Public License cover the whole
combination.

As a special exception, the copyright holders of this library give you
permission to link this library with independent modules to produce an
executable, regardless of the license terms of these independent
modules, and to copy and distribute the resulting executable under
terms of your choice, provided that you also meet, for each linked
independent module, the terms and conditions of the license of that
module.  An independent module is a module which is not derived from
or based on this library.  If you modify this library, you may extend
this exception to your version of the library, but you are not
obligated to do so.  If you do not wish to do so, delete this
exception statement from your version.  */

package org.metastatic.treediff;

import gnu.getopt.Getopt;
import gnu.getopt.LongOpt;

import java.io.*;
import java.nio.file.*;
import java.nio.file.attribute.*;
import java.security.DigestInputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.*;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import com.google.common.base.Optional;
import org.metastatic.rsync.*;

public class Main
{
    static final int CHECKSUM = 0x10000 | 's';
    static final int DIFF = 0x10000 | 'd';
    static final int PATCH = 0x10000 | 'p';
    static final int HELP = 0x10000 | 'h';
    static final int VERSION = 0x10000 | 'v';
    private static final byte[] SUMS_MAGIC = new byte[]{'T', 'D', 's', 'u', 'm', 's', 0x00, 0x01};
    private static final byte[] DIFF_MAGIC = new byte[]{'T', 'D', 'd', 'i', 'f', 'f', 0x00, 0x01};

    static int verbosity = 0;

    static enum Command
    {
        Checksum("--checksum"), Diff("--diff"), Patch("--patch");

        private Command(String option)
        {
            this.option = option;
        }

        final String option;

        public String getOption()
        {
            return option;
        }
    }

    static enum DiffCheck
    {
        SizeOnly, SizeAndTime, StrictHash;
    }

    static void checkCommand(String option, Optional<Command> command, EnumSet<Command> expect)
    {
        if (!command.isPresent() || !expect.contains(command.get()))
        {
            System.err.printf("%s: %s: please supply a command", Main.class.getName(), option);
            if (!expect.isEmpty())
            {
                System.err.printf(" (expected ");
                boolean first = true;
                for (Iterator<Command> it = expect.iterator(); it.hasNext(); )
                {
                    Command c = it.next();
                    if (!it.hasNext() && !first)
                        System.err.printf(" or ");
                    System.err.printf("%s", c.getOption());
                    if (it.hasNext())
                        System.err.printf(", ");
                    else
                        System.err.printf(")");
                    first = false;
                }
            }
            System.err.printf(".%n");
            System.exit(1);
        }
    }

    public static void main(String... argv) throws Exception
    {
        Optional<Command> command = Optional.absent();
        LongOpt[] longOpts = new LongOpt[] {
            new LongOpt("checksum", LongOpt.NO_ARGUMENT, null, CHECKSUM),
            new LongOpt("diff", LongOpt.NO_ARGUMENT, null, DIFF),
            new LongOpt("patch", LongOpt.NO_ARGUMENT, null, PATCH),
            new LongOpt("hash", LongOpt.REQUIRED_ARGUMENT, null, 'h'),
            new LongOpt("hash-length", LongOpt.REQUIRED_ARGUMENT, null, 'l'),
            new LongOpt("sums-file", LongOpt.REQUIRED_ARGUMENT, null, 's'),
            new LongOpt("diff-file", LongOpt.REQUIRED_ARGUMENT, null, 'd'),
            new LongOpt("output", LongOpt.REQUIRED_ARGUMENT, null, 'o'),
            new LongOpt("verbose", LongOpt.NO_ARGUMENT, null, 'v'),
            new LongOpt("strict-hash", LongOpt.NO_ARGUMENT, null, 'H'),
            new LongOpt("size-only", LongOpt.NO_ARGUMENT, null, 'S'),
            new LongOpt("help", LongOpt.NO_ARGUMENT, null, HELP),
            new LongOpt("version", LongOpt.NO_ARGUMENT, null, VERSION)
        };
        Optional<MessageDigest> hash = Optional.absent();
        Optional<Integer> hashLength = Optional.absent();
        Optional<String> inputFile = Optional.absent();
        Optional<String> outputFile = Optional.absent();
        Optional<DiffCheck> diffCheck = Optional.of(DiffCheck.SizeAndTime);
        Getopt getopt = new Getopt(Main.class.getName(), argv, "h:l:s:d:o:vH", longOpts);
        int ch;
        while ((ch = getopt.getopt()) != -1)
        {
            switch (ch)
            {
                case CHECKSUM:
                    if (command.isPresent())
                    {
                        System.err.printf("%s: only specify one command.%n", Main.class.getName());
                        System.exit(1);
                        return;
                    }
                    command = Optional.of(Command.Checksum);
                    break;

                case DIFF:
                    if (command.isPresent())
                    {
                        System.err.printf("%s: only specify one command.%n", Main.class.getName());
                        System.exit(1);
                        return;
                    }
                    command = Optional.of(Command.Diff);
                    break;

                case PATCH:
                    if (command.isPresent())
                    {
                        System.err.printf("%s: only specify one command.%n", Main.class.getName());
                        System.exit(1);
                        return;
                    }
                    command = Optional.of(Command.Patch);

                case HELP:
                    help();
                    System.exit(0);
                    break;

                case VERSION:
                    version();
                    System.exit(0);
                    break;

                case 'h':
                    checkCommand("--hash", command, EnumSet.of(Command.Checksum));
                    try
                    {
                        hash = Optional.of(MessageDigest.getInstance(getopt.getOptarg()));
                    }
                    catch (NoSuchAlgorithmException nsae)
                    {
                        try
                        {
                            hash = Optional.of(MessageDigest.getInstance(getopt.getOptarg(), new JarsyncProvider()));
                        }
                        catch (NoSuchAlgorithmException nsae2)
                        {
                            System.err.printf("%s: no such hash: %s%n", Main.class.getName(), getopt.getOptarg());
                            System.exit(1);
                            return;
                        }
                    }
                    break;

                case 'l':
                    checkCommand("--hash-length", command, EnumSet.of(Command.Checksum));
                    try
                    {
                        hashLength = Optional.of(Integer.parseInt(getopt.getOptarg()));
                    }
                    catch (NumberFormatException nfe)
                    {
                        System.err.printf("%s: --hash-length: invalid number.%n", Main.class.getName());
                        System.exit(1);
                        return;
                    }
                    break;

                case 's':
                    checkCommand("--sums-file", command, EnumSet.of(Command.Diff));
                    inputFile = Optional.of(getopt.getOptarg());
                    break;

                case 'd':
                    checkCommand("--diff-file", command, EnumSet.of(Command.Patch));
                    inputFile = Optional.of(getopt.getOptarg());
                    break;

                case 'o':
                    checkCommand("--output", command, EnumSet.of(Command.Checksum, Command.Diff));
                    outputFile = Optional.of(getopt.getOptarg());
                    break;

                case 'v':
                    verbosity++;
                    break;

                case 'H':
                    checkCommand("--strict-hash", command, EnumSet.of(Command.Diff));
                    diffCheck = Optional.of(DiffCheck.StrictHash);
                    break;

                case 'S':
                    checkCommand("--size-only", command, EnumSet.of(Command.Diff));
                    diffCheck = Optional.of(DiffCheck.SizeOnly);
                    break;

                case '?':
                    System.err.printf("Try `%s --help' for more info.%n", Main.class.getName());
                    System.exit(1);
                    return;
            }
        }

        if (!command.isPresent())
        {
            System.err.printf("%s: must supply a command.%n", Main.class.getName());
            System.exit(1);
            return;
        }

        switch (command.get())
        {
            case Checksum:
            {
                if (!hash.isPresent())
                    hash = Optional.of(MessageDigest.getInstance("Murmur3", new JarsyncProvider()));
                if (!hashLength.isPresent())
                    hashLength = Optional.of(hash.get().getDigestLength());
                else if (hashLength.get() <= 0 || hashLength.get() > hash.get().getDigestLength())
                {
                    System.err.printf("%s: invalid hash length: %d.%n", Main.class.getName(), hashLength.get());
                    System.exit(1);
                    return;
                }
                if (!outputFile.isPresent())
                {
                    System.err.printf("%s: --output argument required.%n", Main.class.getName());
                    System.exit(1);
                    return;
                }
                if (getopt.getOptind() >= argv.length)
                {
                    System.err.printf("%s: must specify at least one file or directory.%n", Main.class.getName());
                    System.exit(1);
                    return;
                }
                DataOutputStream output = new DataOutputStream(new BufferedOutputStream(new FileOutputStream(outputFile.get())));
                output.write(SUMS_MAGIC);
                String alg = hash.get().getAlgorithm();
                output.writeUTF(alg);
                output.writeInt(hashLength.get());
                checksum(hash.get(), hashLength.get(), output, Arrays.asList(argv).subList(getopt.getOptind(), argv.length));
                output.close();
                break;
            }

            case Diff:
            {
                if (!inputFile.isPresent())
                {
                    System.err.printf("%s: --diff: option --sums-file required.%n", Main.class.getName());
                    System.exit(1);
                    return;
                }
                if (!outputFile.isPresent())
                {
                    System.err.printf("%s: --output argument required.%n", Main.class.getName());
                    System.exit(1);
                    return;
                }
                DataInputStream input = new DataInputStream(new FileInputStream(inputFile.get()));
                byte[] magic = new byte[8];
                input.readFully(magic);
                if (!Arrays.equals(magic, SUMS_MAGIC))
                {
                    System.err.printf("%s: %s: invalid file header.%n", Main.class.getName(), inputFile.get());
                    System.exit(1);
                    return;
                }
                String alg = input.readUTF();
                try
                {
                    hash = Optional.of(MessageDigest.getInstance(alg, new JarsyncProvider()));
                }
                catch (NoSuchAlgorithmException nsae)
                {
                    hash = Optional.of(MessageDigest.getInstance(alg));
                }
                hashLength = Optional.of(input.readInt());
                if (hashLength.get() <= 0 || hashLength.get() > hash.get().getDigestLength())
                {
                    System.err.printf("%s: invalid hash length: %d.%n", Main.class.getName(), hashLength.get());
                    System.exit(1);
                    return;
                }
                DataOutputStream output = new DataOutputStream(new BufferedOutputStream(new FileOutputStream(outputFile.get())));
                output.write(DIFF_MAGIC);
                output.writeUTF(alg);
                output.writeInt(hashLength.get());
                diff(hash.get(), hashLength.get(), input, output, diffCheck.or(DiffCheck.SizeAndTime));
                output.close();
                break;
            }

            case Patch:
                throw new Error("not yet implemented");
        }
    }

    static short permBits(Set<PosixFilePermission> perms)
    {
        short result = 0;
        if (perms.contains(PosixFilePermission.OWNER_READ)) result |= 1 << 8;
        if (perms.contains(PosixFilePermission.OWNER_WRITE)) result |= 1 << 7;
        if (perms.contains(PosixFilePermission.OWNER_EXECUTE)) result |= 1 << 6;
        if (perms.contains(PosixFilePermission.GROUP_READ)) result |= 1 << 5;
        if (perms.contains(PosixFilePermission.GROUP_WRITE)) result |= 1 << 4;
        if (perms.contains(PosixFilePermission.GROUP_EXECUTE)) result |= 1 << 3;
        if (perms.contains(PosixFilePermission.OTHERS_READ)) result |= 1 << 2;
        if (perms.contains(PosixFilePermission.OTHERS_WRITE)) result |= 1 << 1;
        if (perms.contains(PosixFilePermission.OTHERS_EXECUTE)) result |= 1;
        return result;
    }

    static void checksum(MessageDigest hash, int hashLength, DataOutputStream output, List<String> f) throws IOException
    {
        Configuration.Builder builder = Configuration.Builder.create();
        builder.strongSum(hash);
        builder.strongSumLength(hashLength);

        FileVisitor<Path> visitor = new SimpleFileVisitor<Path>()
        {
            @Override
            public FileVisitResult preVisitDirectory(Path dir, BasicFileAttributes attrs) throws IOException
            {
                return visitFile(dir, attrs);
            }

            @Override
            public FileVisitResult visitFile(Path file, BasicFileAttributes attrs) throws IOException
            {
                if (verbosity > 0)
                    System.out.printf("visiting file: %s%n", file.toFile().getAbsolutePath());
                String user = "", group = "";
                short permissions = 0;
                try
                {
                    PosixFileAttributes posixAttr = null;
                    if (attrs instanceof PosixFileAttributes)
                        posixAttr = (PosixFileAttributes) attrs;
                    else
                        posixAttr = Files.getFileAttributeView(file, PosixFileAttributeView.class, LinkOption.NOFOLLOW_LINKS).readAttributes();
                    user = posixAttr.owner().getName();
                    group = posixAttr.group().getName();
                    permissions = permBits(posixAttr.permissions());
                }
                catch (Exception x)
                {
                    // ignore
                }

                if (attrs.isRegularFile())
                {
                    // Format is:
                    // 'f'
                    // user, group, permissions, file size
                    // file path, UTF-8 (length + bytes)
                    // block length
                    // 's' weakSum, strongSum, offset, length
                    // 0 -- end of stream.
                    if (verbosity > 1)
                        System.out.printf("%s: emitting file sums.%n", file.toFile());
                    output.write('f');
                    output.writeUTF(user);
                    output.writeUTF(group);
                    output.writeShort(permissions);
                    writeFileAttributes(file, attrs, output);
                    output.writeUTF(file.toFile().getAbsolutePath());
                    // Choose a block size.
                    int blockLength = 0;
                    if (Files.size(file) <= 2048)
                        blockLength = Math.max(512, (int) Files.size(file) / 10);
                    else if (Files.size(file) <= 20 * 1024 * 1024)
                        blockLength = Math.max(2048, (int) Files.size(file) / 100);
                    else
                        blockLength = (int) Math.min(1024L * 1024L, Files.size(file) / 1000);
                    builder.blockLength(blockLength);
                    output.writeInt(blockLength);
                    Configuration config = builder.build();
                    GeneratorStream gen = new GeneratorStream(config);
                    AtomicInteger sumCount = new AtomicInteger(0);
                    gen.addListener((event) -> {
                        ChecksumLocation loc = event.getChecksumLocation();
                        try
                        {
                            output.write('s');
                            output.writeInt(loc.getChecksumPair().getWeak());
                            output.write(loc.getChecksumPair().getStrong());
                            output.writeLong(loc.getOffset());
                            output.writeLong(loc.getLength());
                            sumCount.incrementAndGet();
                        }
                        catch (IOException e)
                        {
                            throw new ListenerException(e);
                        }
                    });
                    MessageDigest fileHash;
                    try
                    {
                        fileHash = MessageDigest.getInstance("MD5");
                    }
                    catch (NoSuchAlgorithmException e)
                    {
                        throw new IOException(e);
                    }
                    byte[] buffer = new byte[4096];
                    int read = 0;
                    DigestInputStream in = new DigestInputStream(new FileInputStream(file.toFile()), fileHash);
                    while ((read = in.read(buffer)) > 0)
                    {
                        try
                        {
                            gen.update(buffer, 0, read);
                        }
                        catch (ListenerException e)
                        {
                            Throwable cause = e.getCause();
                            if (cause instanceof IOException)
                                throw (IOException) cause;
                            throw new IOException(e);
                        }
                    }
                    try
                    {
                        gen.doFinal();
                    }
                    catch (ListenerException e)
                    {
                        Throwable cause = e.getCause();
                        if (cause instanceof IOException)
                            throw (IOException) cause;
                        throw new IOException(e);
                    }
                    output.write('i');
                    byte[] digest = fileHash.digest();
                    output.write(digest);
                    output.write(0);
                    if (verbosity > 1)
                        System.out.printf("%s: wrote %d sums, MD5: %s%n", file.toFile(), sumCount.get(),
                                Util.toHexString(digest));
                }
                else if (attrs.isSymbolicLink())
                {
                    if (verbosity > 1)
                        System.out.printf("%s: emitting symbolic link%n", file.toFile());
                    output.write('l');
                    output.writeUTF(user);
                    output.writeUTF(group);
                    output.writeShort(permissions);
                    writeFileAttributes(file, attrs, output);
                    output.writeUTF(file.toFile().getAbsolutePath());
                    String target = Files.readSymbolicLink(file).toFile().getPath();
                    output.writeUTF(target);
                }
                else if (attrs.isDirectory())
                {
                    // format
                    // 'd'
                    // user, group (UTF-8, length+bytes)
                    // permission string (utf-8, length+bytes)
                    // absolute path (UTF-8, length+bytes)
                    if (verbosity > 1)
                        System.out.printf("%s: emitting directory%n", file.toFile());
                    output.write('d');
                    output.writeUTF(user);
                    output.writeUTF(group);
                    output.writeShort(permissions);
                    writeFileAttributes(file, attrs, output);
                    output.writeUTF(file.toFile().getAbsolutePath());
                }
                else
                {
                    System.out.printf("skipping file: %s%n", file.toFile().getAbsolutePath());
                }
                return FileVisitResult.CONTINUE;
            }
        };
        for (String s : f)
        {
            Path path = Paths.get(s).toAbsolutePath();
            File file = path.toFile();
            if (file.isFile())
            {
                visitor.visitFile(path, Files.readAttributes(path, BasicFileAttributes.class));
            }
            else if (file.isDirectory())
            {
                output.write('r');
                output.writeUTF(path.toFile().getAbsolutePath());
                Files.walkFileTree(path, visitor);
            }
            else
            {
                System.err.printf("skipping non-file, non-folder: %s%n", path);
            }
        }
    }

    private static void writeFileAttributes(Path file, BasicFileAttributes attrs, DataOutputStream output) throws IOException {
        output.writeLong(attrs.creationTime().to(TimeUnit.SECONDS));
        output.writeLong(attrs.lastModifiedTime().to(TimeUnit.SECONDS));
        if (attrs.isRegularFile() || attrs.isDirectory())
            output.writeLong(Files.size(file));
        else if (attrs.isSymbolicLink())
            output.writeLong(Files.readSymbolicLink(file).toFile().getPath().length());
        else
            output.writeLong(0);
    }

    static EnumSet<PosixFilePermission> getPerms(short permBits)
    {
        EnumSet<PosixFilePermission> perms = EnumSet.noneOf(PosixFilePermission.class);
        if ((permBits & (1 << 8)) != 0)
            perms.add(PosixFilePermission.OWNER_READ);
        if ((permBits & (1 << 7)) != 0)
            perms.add(PosixFilePermission.OWNER_WRITE);
        if ((permBits & (1 << 6)) != 0)
            perms.add(PosixFilePermission.OWNER_EXECUTE);
        if ((permBits & (1 << 5)) != 0)
            perms.add(PosixFilePermission.GROUP_READ);
        if ((permBits & (1 << 4)) != 0)
            perms.add(PosixFilePermission.GROUP_WRITE);
        if ((permBits & (1 << 3)) != 0)
            perms.add(PosixFilePermission.GROUP_EXECUTE);
        if ((permBits & (1 << 2)) != 0)
            perms.add(PosixFilePermission.OTHERS_READ);
        if ((permBits & (1 << 1)) != 0)
            perms.add(PosixFilePermission.OTHERS_WRITE);
        if ((permBits &       1)  != 0)
            perms.add(PosixFilePermission.OTHERS_EXECUTE);
        return perms;
    }

    static void skipSums(DataInputStream input, int hashLength) throws IOException
    {
        int c;
        while ((c = input.read()) == 's')
            input.skipBytes(4 + hashLength + 8 + 8);
        if (c == 'i')
        {
            input.skipBytes(16);
            c = input.read();
        }
        if (c != 0)
            throw new IOException("file format error");
    }

    static List<String> toList(Path p)
    {
        List<String> l = new ArrayList<>();
        for (Path aP : p) l.add(aP.toString());
        return l;
    }

    static void diff(MessageDigest hash, int hashLength, DataInputStream input, DataOutputStream output, DiffCheck check) throws IOException, NoSuchAlgorithmException
    {
        Configuration.Builder builder = Configuration.Builder.create();
        builder.strongSum(hash);
        builder.strongSumLength(hashLength);
        Set<Path> roots = new HashSet<>();
        PathTrie visited = new PathTrie();
        int ch;
        while ((ch = input.read()) != -1)
        {
            if (ch == 'r')
            {
                roots.add(Paths.get(input.readUTF()));
                continue;
            }

            if (ch != 'd' && ch != 'f' && ch != 'l')
                throw new IOException(String.format("invalid tag: %02x", ch));
            String owner = input.readUTF();
            String group = input.readUTF();
            EnumSet<PosixFilePermission> perms = getPerms(input.readShort());
            FileTime created = FileTime.from(input.readLong(), TimeUnit.SECONDS);
            FileTime modified = FileTime.from(input.readLong(), TimeUnit.SECONDS);
            long fileSize = input.readLong();
            Path path = Paths.get(input.readUTF());
            visited.add(toList(path));

            if (verbosity > 1)
            {
                System.out.printf("tag: %c, owner: %s, group: %s, perms: %s, created: %s, modified: %s, size: %d, path: %s%n",
                        (char) ch, owner, group, perms, created, modified, fileSize, path.toFile());
            }

            BasicFileAttributes basicAttrs = null;
            try
            {
                basicAttrs = Files.readAttributes(path, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
            }
            catch (NoSuchFileException x)
            {
                // skip file not found
            }
            if (basicAttrs == null)
            {
                // Delete
                if (verbosity > 0)
                    System.out.printf("%s: file does not exist, emitting delete.%n", path.toFile());
                output.write('X');
                output.writeUTF(path.toFile().getPath());
                if (ch == 'f')
                {
                    input.readInt(); // skip block length
                    skipSums(input, hashLength);
                }
                else if (ch == 'l')
                    input.readUTF(); // skip link target
                continue;
            }

            if (ch == 'f')
            {
                int blockLength = input.readInt();
                PosixFileAttributes attrs = Files.getFileAttributeView(path, PosixFileAttributeView.class, LinkOption.NOFOLLOW_LINKS).readAttributes();
                if (attrs.isRegularFile())
                {
                    if (check == DiffCheck.SizeOnly && fileSize == Files.size(path))
                    {
                        if (verbosity > 0)
                            System.out.printf("%s: skipping file, file sizes match.%n", path.toFile());
                        skipSums(input, hashLength);
                        continue;
                    }
                    if (check == DiffCheck.SizeAndTime && fileSize == Files.size(path) && modified.equals(attrs.lastModifiedTime()))
                    {
                        if (verbosity > 0)
                            System.out.printf("%s: skipping file, file sizes and times match.%n", path.toFile());
                        skipSums(input, hashLength);
                        continue;
                    }

                    List<ChecksumLocation> locations = new ArrayList<>();
                    int c;
                    while ((c = input.read()) == 's')
                    {
                        int weak = input.readInt();
                        byte[] strong = new byte[hashLength];
                        input.readFully(strong);
                        long offset = input.readLong();
                        long length = input.readLong();
                        locations.add(new ChecksumLocation(new ChecksumPair(weak, strong), offset, (int) length));
                    }
                    byte[] fileDigest = new byte[16];
                    if (c == 'i')
                    {
                        input.readFully(fileDigest);
                        c = input.read();
                        if (check == DiffCheck.StrictHash)
                        {
                            MessageDigest fileHash = MessageDigest.getInstance("MD5");
                            InputStream in = Files.newInputStream(path, StandardOpenOption.READ);
                            byte[] buffer = new byte[4096];
                            int read;
                            while ((read = in.read(buffer)) >= 0)
                                fileHash.update(buffer, 0, read);
                            byte[] digest2 = fileHash.digest();
                            if (Arrays.equals(fileDigest, digest2))
                            {
                                if (verbosity > 0)
                                    System.out.printf("%s: skipping file, file MD5 matches.%n", path.toFile());
                                continue;
                            }
                        }
                    }
                    if (c != 0)
                        throw new IOException(String.format("invalid sum tag: %02x", c));

                    // write a patch command
                    output.write('p');
                    output.writeUTF(attrs.owner().getName());
                    output.writeUTF(attrs.group().getName());
                    output.writeShort(permBits(attrs.permissions()));
                    writeFileAttributes(path, attrs, output);
                    output.writeUTF(path.toFile().getAbsolutePath());
                    MatcherStream matcherStream = new MatcherStream(builder.blockLength(blockLength).build());
                    matcherStream.addListener((event) -> {
                        Delta delta = event.getDelta();
                        if (delta instanceof Offsets)
                        {
                            try
                            {
                                output.write('o');
                                output.writeInt(((Offsets) delta).getBlockLength());
                                output.writeLong(((Offsets) delta).getOldOffset());
                                output.writeLong(((Offsets) delta).getNewOffset());
                            }
                            catch (IOException e)
                            {
                                throw new ListenerException(e);
                            }
                        }
                        else if (delta instanceof DataBlock)
                        {
                            try
                            {
                                output.write('d');
                                output.writeInt(((DataBlock) delta).getBlockLength());
                                output.writeLong(((DataBlock) delta).getOffset());
                                output.write(((DataBlock) delta).getData());
                            }
                            catch (IOException e)
                            {
                                throw new ListenerException(e);
                            }
                        }
                    });
                    matcherStream.setChecksums(locations);
                    FileInputStream in = new FileInputStream(path.toFile());
                    byte[] buffer = new byte[4096];
                    int read;
                    while ((read = in.read(buffer)) > 0)
                    {
                        try
                        {
                            matcherStream.update(buffer, 0, read);
                        }
                        catch (ListenerException e)
                        {
                            if (e.getCause() instanceof IOException)
                                throw (IOException) e.getCause();
                            throw new IOException(e);
                        }
                    }
                    try
                    {
                        matcherStream.doFinal();
                    }
                    catch (ListenerException e)
                    {
                        if (e.getCause() instanceof IOException)
                            throw (IOException) e.getCause();
                        throw new IOException(e);
                    }
                    output.write(0);
                }
                else if (attrs.isSymbolicLink())
                {
                    // Emit command to overwrite any -> symlink
                    output.write('L');
                    output.writeUTF(attrs.owner().getName());
                    output.writeUTF(attrs.group().getName());
                    output.writeShort(permBits(attrs.permissions()));
                    writeFileAttributes(path, attrs, output);
                    output.writeUTF(path.toFile().getAbsolutePath());
                    output.writeUTF(Files.readSymbolicLink(path).toFile().getPath());
                    skipSums(input, hashLength);
                }
                else if (attrs.isDirectory())
                {
                    // Emit command to overwrite any -> directory
                    output.write('D');
                    output.writeUTF(attrs.owner().getName());
                    output.writeUTF(attrs.group().getName());
                    output.writeShort(permBits(attrs.permissions()));
                    writeFileAttributes(path, attrs, output);
                    output.writeUTF(path.toFile().getAbsolutePath());
                    skipSums(input, hashLength);
                }
                else
                {
                    if (verbosity > 0)
                        System.out.printf("%s: skipping file, not a file, directory, or link.%n", path.toFile());
                }
            }
            else if (ch == 'l')
            {
                Path target = Paths.get(input.readUTF());
                PosixFileAttributes attrs = Files.getFileAttributeView(path, PosixFileAttributeView.class, LinkOption.NOFOLLOW_LINKS).readAttributes();
                if (attrs.isRegularFile())
                {
                    // New file, overwriting a symlink.
                    output.write('F');
                    output.writeUTF(attrs.owner().getName());
                    output.writeUTF(attrs.group().getName());
                    output.writeShort(permBits(attrs.permissions()));
                    writeFileAttributes(path, attrs, output);
                    output.writeUTF(path.toFile().getAbsolutePath());
                    InputStream in = Files.newInputStream(path, StandardOpenOption.READ);
                    long total = Files.size(path);
                    int read;
                    byte[] buffer = new byte[4096];
                    while ((read = in.read(buffer, 0, (int) Math.min(buffer.length, total))) >= 0 && total > 0)
                    {
                        output.write(buffer, 0, read);
                        total -= read;
                    }
                }
                else if (attrs.isSymbolicLink())
                {
                    Path otherTarget = Files.readSymbolicLink(path);
                    if (!target.equals(otherTarget) || !owner.equals(attrs.owner().getName())
                        || !group.equals(attrs.group().getName())
                        || !perms.equals(attrs.permissions())
                        || !modified.equals(attrs.lastModifiedTime())
                        || !created.equals(attrs.creationTime()))
                    {
                        if (verbosity > 0)
                            System.out.printf("%s: update link target to %s.%n", path.toFile(), otherTarget);
                        if (verbosity > 1)
                            System.out.printf("  owner: %s vs %s%n" +
                                            "  group: %s vs %s%n" +
                                            "  perms: %s vs %s%n" +
                                            "  modified: %s vs %s%n" +
                                            "  created: %s vs %s%n",
                                    owner, attrs.owner().getName(), group, attrs.group().getName(),
                                    perms, attrs.permissions(),
                                    modified, attrs.lastModifiedTime(),
                                    created, attrs.creationTime());
                        output.write('L');
                        output.writeUTF(attrs.owner().getName());
                        output.writeUTF(attrs.group().getName());
                        output.writeShort(permBits(attrs.permissions()));
                        writeFileAttributes(path, attrs, output);
                        output.writeUTF(path.toFile().getAbsolutePath());
                        output.writeUTF(otherTarget.toFile().getPath());
                    }
                    else
                    {
                        if (verbosity > 0)
                            System.out.printf("%s: not updating link.%n", path.toFile());
                    }
                }
                else if (attrs.isDirectory())
                {
                    output.write('D');
                    output.writeUTF(attrs.owner().getName());
                    output.writeUTF(attrs.group().getName());
                    output.writeShort(permBits(attrs.permissions()));
                    writeFileAttributes(path, attrs, output);
                    output.writeUTF(path.toFile().getAbsolutePath());
                }
            }
            else if (ch == 'd')
            {
                PosixFileAttributes attrs = Files.getFileAttributeView(path, PosixFileAttributeView.class, LinkOption.NOFOLLOW_LINKS).readAttributes();
                if (attrs.isRegularFile())
                {
                    // New file, overwriting a directory.
                    output.write('F');
                    output.writeUTF(attrs.owner().getName());
                    output.writeUTF(attrs.group().getName());
                    output.writeShort(permBits(attrs.permissions()));
                    writeFileAttributes(path, attrs, output);
                    output.writeUTF(path.toFile().getAbsolutePath());
                    InputStream in = Files.newInputStream(path, StandardOpenOption.READ);
                    long total = Files.size(path);
                    int read;
                    byte[] buffer = new byte[4096];
                    while ((read = in.read(buffer, 0, (int) Math.min(buffer.length, total))) >= 0 && total > 0)
                    {
                        output.write(buffer, 0, read);
                        total -= read;
                    }
                }
                else if (attrs.isSymbolicLink())
                {
                    output.write('L');
                    output.writeUTF(attrs.owner().getName());
                    output.writeUTF(attrs.group().getName());
                    output.writeShort(permBits(attrs.permissions()));
                    writeFileAttributes(path, attrs, output);
                    output.writeUTF(path.toFile().getAbsolutePath());
                    output.writeUTF(Files.readSymbolicLink(path).toFile().getPath());
                }
                else if (attrs.isDirectory())
                {
                    if (!owner.equals(attrs.owner().getName())
                        || !group.equals(attrs.group().getName())
                        || !perms.equals(attrs.permissions())
                        || !modified.equals(attrs.lastModifiedTime())
                        || !created.equals(attrs.creationTime()))
                    {
                        if (verbosity > 0)
                            System.out.printf("%s: updating directory metadata%n", path.toFile());
                        if (verbosity > 1)
                            System.out.printf("  owner: %s vs %s%n" +
                                              "  group: %s vs %s%n" +
                                              "  perms: %s vs %s%n" +
                                              "  modified: %s vs %s%n" +
                                              "  created: %s vs %s%n",
                                              owner, attrs.owner().getName(), group, attrs.group().getName(),
                                              perms, attrs.permissions(),
                                              modified, attrs.lastModifiedTime(),
                                              created, attrs.creationTime());
                        output.write('D');
                        output.writeUTF(attrs.owner().getName());
                        output.writeUTF(attrs.group().getName());
                        output.writeShort(permBits(attrs.permissions()));
                        writeFileAttributes(path, attrs, output);
                        output.writeUTF(path.toFile().getAbsolutePath());
                    }
                }
            }
        }

        // Now, find any files that exist in our local roots that we haven't already visited.
        for (Path root : roots)
        {
            BasicFileAttributes attr;
            try
            {
                attr = Files.readAttributes(root, BasicFileAttributes.class);
            }
            catch (Exception x)
            {
                continue;
            }

            if (attr.isDirectory())
            {
                Files.walk(root).filter(e -> !visited.contains(toList(e))).forEach(file -> {
                    try
                    {
                        PosixFileAttributes posixAttrs = Files.getFileAttributeView(file, PosixFileAttributeView.class, LinkOption.NOFOLLOW_LINKS).readAttributes();
                        if (verbosity > 0)
                            System.out.printf("%s: visiting new file not from sums.%n", file);
                        if (posixAttrs.isRegularFile())
                        {
                            output.write('F');
                            output.writeUTF(posixAttrs.owner().getName());
                            output.writeUTF(posixAttrs.group().getName());
                            output.writeShort(permBits(posixAttrs.permissions()));
                            writeFileAttributes(file, posixAttrs, output);
                            output.writeUTF(file.toFile().getAbsolutePath());
                            InputStream in = Files.newInputStream(file, StandardOpenOption.READ);
                            long total = Files.size(file);
                            int read;
                            byte[] buffer = new byte[4096];
                            while ((read = in.read(buffer, 0, (int) Math.min(buffer.length, total))) >= 0 && total > 0)
                            {
                                output.write(buffer, 0, read);
                                total -= read;
                            }
                        } else if (posixAttrs.isSymbolicLink())
                        {
                            output.write('L');
                            output.writeUTF(posixAttrs.owner().getName());
                            output.writeUTF(posixAttrs.group().getName());
                            output.writeShort(permBits(posixAttrs.permissions()));
                            writeFileAttributes(file, posixAttrs, output);
                            output.writeUTF(file.toFile().getAbsolutePath());
                            output.writeUTF(Files.readSymbolicLink(file).toFile().getPath());
                        } else if (posixAttrs.isDirectory())
                        {
                            output.write('D');
                            output.writeUTF(posixAttrs.owner().getName());
                            output.writeUTF(posixAttrs.group().getName());
                            output.writeShort(permBits(posixAttrs.permissions()));
                            writeFileAttributes(file, posixAttrs, output);
                            output.writeUTF(file.toFile().getAbsolutePath());
                        }
                    }
                    catch (IOException ioe)
                    {
                        throw new RuntimeException(ioe);
                    }
                });
            }
        }
    }

    static void help()
    {
        System.out.printf("usage: %s <command> [options] [list of directories...]%n%n" +
                          "Commands include:%n" +
                          "  --checksum       Generate checksums for all files in given directories.%n" +
                          "  --diff           Take in checksums list, generate diff against local files.%n" +
                          "  --patch          Take in diffs, patch local files with differences.%n" +
                          "  --help           Show this help and exit.%n" +
                          "  --version        Print version number and exit.%n%n" +
                          "Options include:%n%n" +
                          "  --hash=NAME, -h         Specify MessageDigest to use for --checksum (default: murmur3).%n" +
                          "  --hash-length=LEN, -l   Specify hash length for --checksum, default native hash output length.%n" +
                          "  --sums-file=FILE, -s    Checksum input file, for --diff.%n" +
                          "  --diff-file=FILE, -d    Difference input file, for --patch.%n" +
                          "  --output=FILE, -o       Output file location, for --checksum and --diff.%n" +
                          "  --strict-hash, -H       Compute file MD5 to determine if diffs should be generated.%n" +
                          "  --size-only, -S         Only check file size when determining to generate diffs.%n" +
                          "                          The default behavior is to check the file size and modification times.%n" +
                          "  --verbose, -v           Increase verbosity.%n%n",
                Main.class.getName());
    }

    static void version()
    {
        System.out.printf("%s version 0.0.1%n", Main.class.getName()); // TODO
    }
}

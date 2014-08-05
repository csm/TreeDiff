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

import com.google.common.base.Optional;
import gnu.getopt.Getopt;
import gnu.getopt.LongOpt;
import org.metastatic.rsync.*;

import java.io.*;
import java.nio.file.*;
import java.nio.file.attribute.BasicFileAttributes;
import java.nio.file.attribute.PosixFileAttributeView;
import java.nio.file.attribute.PosixFileAttributes;
import java.nio.file.attribute.PosixFilePermission;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.*;

public class Main
{
    static final int CHECKSUM = 0x10000 | 's';
    static final int DIFF = 0x10000 | 'd';
    static final int PATCH = 0x10000 | 'p';
    static final int HELP = 0x10000 | 'h';
    static final int VERSION = 0x10000 | 'v';

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
            new LongOpt("help", LongOpt.NO_ARGUMENT, null, HELP),
            new LongOpt("version", LongOpt.NO_ARGUMENT, null, VERSION)
        };
        Optional<MessageDigest> hash = Optional.absent();
        Optional<Integer> hashLength = Optional.absent();
        Optional<String> inputFile = Optional.absent();
        Optional<String> outputFile = Optional.absent();
        Getopt getopt = new Getopt(Main.class.getName(), argv, "h:l:s:d:o:v", longOpts);
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
                output.write(new byte[]{'T', 'D', 's', 'u', 'm', 's', 0x00, 0x01});
                String alg = hash.get().getAlgorithm();
                output.writeUTF(alg);
                output.writeInt(hashLength.get());
                checksum(hash.get(), hashLength.get(), output, Arrays.asList(argv).subList(getopt.getOptind(), argv.length));
                output.close();
                break;
            }

            case Diff:

            case Patch:
        }
    }

    static String permString(Set<PosixFilePermission> perms)
    {
        StringBuilder s = new StringBuilder();
        if (perms.contains(PosixFilePermission.OWNER_READ))
            s.append('r');
        else
            s.append('-');
        if (perms.contains(PosixFilePermission.OWNER_WRITE))
            s.append('w');
        else
            s.append('-');
        if (perms.contains(PosixFilePermission.OWNER_EXECUTE))
            s.append('x');
        else
            s.append('-');

        if (perms.contains(PosixFilePermission.GROUP_READ))
            s.append('r');
        else
            s.append('-');
        if (perms.contains(PosixFilePermission.GROUP_WRITE))
            s.append('w');
        else
            s.append('-');
        if (perms.contains(PosixFilePermission.GROUP_EXECUTE))
            s.append('x');
        else
            s.append('-');

        if (perms.contains(PosixFilePermission.OTHERS_READ))
            s.append('r');
        else
            s.append('-');
        if (perms.contains(PosixFilePermission.OTHERS_WRITE))
            s.append('w');
        else
            s.append('-');
        if (perms.contains(PosixFilePermission.OTHERS_EXECUTE))
            s.append('x');
        else
            s.append('-');
        return s.toString();
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
                String user = "", group = "", permissions = "??????";
                try
                {
                    PosixFileAttributes posixAttr = null;
                    if (attrs instanceof PosixFileAttributes)
                        posixAttr = (PosixFileAttributes) attrs;
                    else
                        posixAttr = Files.getFileAttributeView(file, PosixFileAttributeView.class).readAttributes();
                    user = posixAttr.owner().getName();
                    group = posixAttr.group().getName();
                    permissions = permString(posixAttr.permissions());
                }
                catch (Exception x)
                {
                    // ignore
                }

                if (attrs.isRegularFile())
                {
                    // Format is:
                    // 'f'
                    // user, group, permissions
                    // file path, UTF-8 (length + bytes)
                    // block length
                    // 's' weakSum, strongSum, offset, length
                    // 0 -- end of stream.
                    output.write('f');
                    output.writeUTF(user);
                    output.writeUTF(group);
                    output.writeUTF(permissions);
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
                    gen.addListener((event) -> {
                        ChecksumLocation loc = event.getChecksumLocation();
                        try
                        {
                            output.write('s');
                            output.writeInt(loc.getChecksumPair().getWeak());
                            output.write(loc.getChecksumPair().getStrong());
                            output.writeLong(loc.getOffset());
                            output.writeLong(loc.getLength());
                        }
                        catch (IOException e)
                        {
                            throw new ListenerException(e);
                        }
                    });
                    byte[] buffer = new byte[4096];
                    int read = 0;
                    FileInputStream in = new FileInputStream(file.toFile());
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
                    output.write(0);
                }
                else if (attrs.isSymbolicLink())
                {
                    output.write('l');
                    output.writeUTF(user);
                    output.writeUTF(group);
                    output.writeUTF(permissions);
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
                    output.write('d');
                    output.writeUTF(user);
                    output.writeUTF(group);
                    output.writeUTF(permissions);
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
                Files.walkFileTree(path, visitor);
            }
            else
            {
                System.err.printf("skipping non-file, non-folder: %s%n", path);
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
                          "  --verbose, -v           Increase verbosity.%n%n",
                Main.class.getName());
    }

    static void version()
    {
        System.out.printf("%s version 0.0.1%n", Main.class.getName()); // TODO
    }
}

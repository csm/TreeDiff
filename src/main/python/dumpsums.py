import struct
import sys

magic = sys.stdin.read(8)
if magic != b'TDsums\x00\x01':
    print 'invalid magic: %r' % magic
    sys.exit(1)
print 'File version', struct.unpack('>H', magic[-2:])[0]


def readutf(i):
    len = struct.unpack('>H', i.read(2))[0]
    utf = i.read(len)
    return unicode(utf)


def readint(i):
    return struct.unpack('>I', i.read(4))[0]


def readlong(i):
    s = i.read(8)
    return struct.unpack('>Q', s)[0]

alg = readutf(sys.stdin)
print 'Algorithm:', alg

hashlen = readint(sys.stdin)
print 'Hash length:', hashlen

while True:
    x = sys.stdin.read(1)
    if len(x) < 1:
        break
    if x[0] == 'f':
        print 'File entry'
        print '  User:', readutf(sys.stdin)
        print '  Group:', readutf(sys.stdin)
        print '  Perms:', readutf(sys.stdin)
        print '  Path:', readutf(sys.stdin)
        print '  Block length:', readint(sys.stdin)
        print '  Sums:'
        while True:
            x = sys.stdin.read(1)
            if x[0] == 's':
                weak = readint(sys.stdin)
                strong = sys.stdin.read(hashlen)
                offset = readlong(sys.stdin)
                length = readlong(sys.stdin)
                print '    weak=%s, strong=%s, offset=%d, length=%d' % (weak,
                                                                        ''.join(map(lambda c: '%02x' % ord(c), strong)),
                                                                        offset, length)
            elif ord(x[0]) == 0:
                break
            else:
                print 'unknown sum entry %r' % x[0]
    elif x[0] == 'l':
        print 'Symlink entry'
        print '  User:', readutf(sys.stdin)
        print '  Group:', readutf(sys.stdin)
        print '  Perms:', readutf(sys.stdin)
        print '  Path:', readutf(sys.stdin)
        print '  Target:', readutf(sys.stdin)
    elif x[0] == 'd':
        print 'Directory entry'
        print '  User:', readutf(sys.stdin)
        print '  Group:', readutf(sys.stdin)
        print '  Perms:', readutf(sys.stdin)
        print '  Path:', readutf(sys.stdin)
    else:
        print 'unknown tag %r' % x[0]
        sys.exit(1)
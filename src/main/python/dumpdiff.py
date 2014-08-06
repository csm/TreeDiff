import base64
import struct
import sys

magic = sys.stdin.read(8)
if magic != b'TDdiff\x00\x01':
    print 'invalid magic: %r' % magic
    sys.exit(1)
print 'File version', struct.unpack('>H', magic[-2:])[0]


def readutf(i):
    len = struct.unpack('>H', i.read(2))[0]
    utf = i.read(len)
    return unicode(utf)


def readshort(i):
    return struct.unpack('>H', i.read(2))[0]


def readint(i):
    return struct.unpack('>I', i.read(4))[0]


def readlong(i):
    s = i.read(8)
    return struct.unpack('>Q', s)[0]


def readfileinfo(i):
    print '  Owner:', readutf(i)
    print '  Group:', readutf(i)
    print '  Perms:', bin(readshort(i))
    print '  Created:', readlong(i)
    print '  Modified:', readlong(i)
    l = readlong(i)
    print '  Size:', l
    print '  Name:', readutf(i)
    return l

alg = readutf(sys.stdin)
print 'Hash:', alg

hashlen = readint(sys.stdin)
print 'Hash len:', hashlen

while True:
    x = sys.stdin.read(1)
    if len(x) < 1:
        break
    if x[0] == 'X':
        print 'Delete file', readutf(sys.stdin)
    elif x[0] == 'p':
        print 'Patch file'
        readfileinfo(sys.stdin)
        while True:
            y = sys.stdin.read(1)
            if y[0] == 'o':
                print 'Copy command len=%d oldoffset=%d newoffset=%d' % (readint(sys.stdin), readlong(sys.stdin),
                                                                         readlong(sys.stdin))
            elif y[0] == 'd':
                l = readint(sys.stdin)
                print 'Data command len=%d offset=%d data=%s' % (l, readlong(sys.stdin),
                                                                 base64.b64encode(sys.stdin.read(l)[0:32]))
            elif y[0] == 0:
                break
            else:
                print 'invalid patch command %x' % ord(y[0])
    elif x[0] == 'L':
        print 'Overwrite with symlink'
        readfileinfo(sys.stdin)
        print 'Target:', readutf(sys.stdin)
    elif x[0] == 'D':
        print 'Overwrite with directory'
        readfileinfo(sys.stdin)
    elif x[0] == 'F':
        print 'Write new file'
        l = readfileinfo(sys.stdin)
        print '  Data:', base64.b64encode(sys.stdin.read(l)[0:32])
    else:
        print 'Invalid tag', hex(ord(x[0]))
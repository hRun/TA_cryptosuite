ALPHABET = b'123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'

# Python2
if bytes == str:
    iseq, bseq, buffer = (
        lambda s: map(ord, s),
        lambda s: ''.join(map(chr, s)),
        lambda s: s,
    )
# Python3
else:
    iseq, bseq, buffer = (
        lambda s: s,
        bytes,
        lambda s: s.buffer,
    )

def sanitize(i):
    if isinstance(i, str) and not isinstance(i, bytes):
        i = i.encode('ascii')

    return i


def b58encode_int(m):
    c = b''

    while m:
        m, i = divmod(m, 58)
        c    = ALPHABET[i:i+1] + c

    return c


def b58encode(m):
    m       = sanitize(m)
    pad_len = len(m) - len(m.lstrip(b'\0'))
    m       = m.lstrip(b'\0')
    p, c    = 1, 0

    for i in iseq(reversed(m)):
        c += p * i
        p  = p << 8

    return (ALPHABET[0:1] * pad_len + b58encode_int(c))


def b58decode_int(c):
    c = c.rstrip()
    c = sanitize(c)
    m = 0

    for i in c:
        m = m * 58 + ALPHABET.index(i)

    return m


def b58decode(c):
    c       = sanitize(c.rstrip())
    pad_len = len(c) - len(c.lstrip(ALPHABET[0:1]))
    c       = c.lstrip(ALPHABET[0:1])
    i       = b58decode_int(c)
    m       = []

    while i > 0:
        i, mod = divmod(i, 256)
        m.append(mod)

    return (b'\0' * pad_len + bseq(reversed(m)))


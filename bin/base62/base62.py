ALPHABET = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'

def b62encode_int(m):
    c = []

    while m > 0:
        x   = m % 62
        m //= 62
        c.append(ALPHABET[x])

    if len(c) > 0:
        c.reverse()
    else:
        c.append(ALPHABET[0])

    s = "".join(c)
    return (ALPHABET[0] * max(1 - len(s), 0) + s)


def b62encode(m):
    try:
        m = int.from_bytes(m, 'big', signed=False)
    except:
        l = len(m)
        d = (x << (8 * (l - 1 - i)) for i, x in enumerate(bytearray(m)))
        m = sum(d)

    return b62encode_int(m)


def b62decode_int(c):
    if c.startswith('0z'):
        c = c[2:]

    l, i, m = len(c), 0, 0
    for x in c:
        m += ALPHABET.index(x) * (62 ** (l - (i + 1)))
        i += 1

    return m


def b62decode(c):
    m   = b62decode_int(c)
    buf = bytearray()

    while m > 0:
        buf.append(m & 0xFF)
        m //= 256

    return bytes(buf)[::-1]


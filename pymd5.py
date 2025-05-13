import struct
import math

# === Constants ===
S = [
    7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
    5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
    4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
    6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
]
K = [int(abs(math.sin(i + 1)) * 2**32) & 0xFFFFFFFF for i in range(64)]
INIT_STATE = (0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476)

def padding(msg_bits):
    index = (msg_bits >> 3) & 0x3f
    pad_len = 56 - index if index < 56 else 120 - index
    return b'\x80' + b'\x00' * (pad_len - 1) + struct.pack('<Q', msg_bits)

def left_rotate(x, c):
    return ((x << c) | (x >> (32 - c))) & 0xFFFFFFFF

def _encode(state):
    return struct.pack('<4I', *state)

def _decode(digest):
    return struct.unpack('<4I', digest)

class md5:
    digest_size = 16
    block_size = 64

    def __init__(self, message=b'', state=None, count=0):
        self._buffer = b''
        self._count = count
        self._state = list(INIT_STATE if state is None else _decode(state))
        if message:
            self.update(message)

    def update(self, data):
        self._buffer += data
        self._count += len(data) * 8
        while len(self._buffer) >= 64:
            self._compress(self._buffer[:64])
            self._buffer = self._buffer[64:]

    def _compress(self, block):
        a, b, c, d = self._state
        x = list(struct.unpack('<16I', block))

        for i in range(64):
            if 0 <= i <= 15:
                f = (b & c) | (~b & d)
                g = i
            elif 16 <= i <= 31:
                f = (d & b) | (~d & c)
                g = (5 * i + 1) % 16
            elif 32 <= i <= 47:
                f = b ^ c ^ d
                g = (3 * i + 5) % 16
            else:
                f = c ^ (b | ~d)
                g = (7 * i) % 16

            temp = (a + f + K[i] + x[g]) & 0xFFFFFFFF
            a, d, c, b = d, c, b, (b + left_rotate(temp, S[i])) & 0xFFFFFFFF

        self._state[0] = (self._state[0] + a) & 0xFFFFFFFF
        self._state[1] = (self._state[1] + b) & 0xFFFFFFFF
        self._state[2] = (self._state[2] + c) & 0xFFFFFFFF
        self._state[3] = (self._state[3] + d) & 0xFFFFFFFF

    def digest(self):
        saved_state = self._state[:]
        saved_buffer = self._buffer
        saved_count = self._count

        self.update(padding(self._count))
        result = _encode(self._state)

        self._state = saved_state
        self._buffer = saved_buffer
        self._count = saved_count
        return result

    def hexdigest(self):
        return self.digest().hex()

# Test
if __name__ == "__main__":
    m = md5(b"example")
    print("MD5('example') =", m.hexdigest())

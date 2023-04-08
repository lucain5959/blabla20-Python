import struct

def blabla20_keystream(n, nonce, key):
    assert len(nonce) == 16
    assert len(key) == 32
    # Initialize the state with constants and key and nonce
  
    state = [0x6170786593810fab, 0x3320646ec7398aee, 0x79622d3217318274, 0x6b206574babadada,
             struct.unpack('<Q', key[0:8])[0], struct.unpack('<Q', key[8:16])[0], struct.unpack('<Q', key[16:24])[0], 
	     struct.unpack('<Q', key[24:32])[0], 0x2ae36e593e46ad5f,  0xb68f143029225fc9, 0x8da1e08468303aa6,
             0xa48a209acd50a4a7, 0x7fdc12f23f90778c, 1,struct.unpack('<Q',nonce[0:8])[0], struct.unpack('<Q',nonce[8:16])[0]]
    # Generate keystream
    out = bytearray(n)
    for i in range(0, n, 64):
        crypto_stream_blabla20_update(state)
        block = struct.pack("<16Q", *(v & 0xffffffffffffffff for v in state))
        out[i:i+64] = block[:min(n-i, 64)]
    return (out)

    #Update the state
def crypto_stream_blabla20_update(st):
    ks = list(st)
    crypto_stream_blabla20_rounds(st)
    for i in range(16):
        ks[i] += st[i]
    st[13] += 1
    st[14] = 0 if st[14] == 0xffffffffffffffff else st[14]
    
    #State is transformed using rounds from blake
def crypto_stream_blabla20_rounds(st):
    for i in range(0, 20, 2):
        CRYPTO_STREAM_BLABLA20_QUARTERROUND(st, 0, 4, 8, 12)
        CRYPTO_STREAM_BLABLA20_QUARTERROUND(st, 1, 5, 9, 13)
        CRYPTO_STREAM_BLABLA20_QUARTERROUND(st, 2, 6, 10, 14)
        CRYPTO_STREAM_BLABLA20_QUARTERROUND(st, 3, 7, 11, 15)
        CRYPTO_STREAM_BLABLA20_QUARTERROUND(st, 0, 5, 10, 15)
        CRYPTO_STREAM_BLABLA20_QUARTERROUND(st, 1, 6, 11, 12)
        CRYPTO_STREAM_BLABLA20_QUARTERROUND(st, 2, 7, 8, 13)
        CRYPTO_STREAM_BLABLA20_QUARTERROUND(st, 3, 4, 9, 14)

def CRYPTO_STREAM_BLABLA20_QUARTERROUND(st, a, b, c, d):
    st[a] += st[b]
    st[d] = ROTR64(st[d] ^ st[a], 32)
    st[c] += st[d]
    st[b] = ROTR64(st[b] ^ st[c], 24)
    st[a] += st[b]
    st[d] = ROTR64(st[d] ^ st[a], 16)
    st[c] += st[d]
    st[b] = ROTR64(st[b] ^ st[c], 63)

def ROTR64(x, b):
    return ((x >> b) | (x << (64 - b))) & 0xffffffffffffffff


def blabla20_encrypt(key, nonce, plaintext):
    # Generate keystream
    keystream = blabla20_keystream(len(plaintext), nonce, key)
    return bytearray(x^y for x, y in zip(plaintext, keystream))
    

key = b'23fa0fe9d5f35203651088076d2f695d'
nonce = b'651088076d2f695d'
plaintext = b'testing!'
ciphertext = blabla20_encrypt(key, nonce, plaintext)
print (ciphertext)

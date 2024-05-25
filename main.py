from pwn import remote
from json import loads, dumps
from base64 import b64decode
from codecs import encode
from Crypto.Util.number import long_to_bytes

r = remote('socket.cryptohack.org', 13377)

while 'flag' not in (encoded := loads(r.recvline().decode())):
    print(encoded)
    r.sendline(dumps({"decoded": {
        'base64': lambda e: b64decode(e).decode(),
        'hex': lambda e: bytes.fromhex(e).decode(),
        'rot13': lambda e: encode(e, 'rot_13'),
        'bigint': lambda e: long_to_bytes(int(e, 16)).decode(),
        'utf-8': lambda e: ''.join([chr(c) for c in e])
    }[encoded['type']](encoded['encoded'])}))


print(encoded['flag'])
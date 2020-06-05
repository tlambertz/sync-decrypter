from Crypto.Cipher import AES
from Crypto.Hash import HMAC, SHA256
from Crypto.Protocol.KDF import HKDF
from Crypto.Util.Padding import pad, unpad
import json

# testcases from https://mozilla-services.readthedocs.io/en/latest/sync/storageformat5.html#record-encryption
master_key = "\xc7\x1a\xa7\xcb\xd8\xb8\x2a\x8f\xf6\xed\xa5\x5c\x39\x47\x9f\xd2"
key1, key2 = HKDF(master_key, 32, None, SHA256, 2, "identity.mozilla.com/picl/v1/oldsync")
print(key1.encode('hex'), key2.encode('hex'))

encryption_key = "d3af449d2dc4b432b8cb5b59d40c8a5fe53b584b16469f5b44828b756ffb6a81".decode('hex')
hmac_key       = "2c5d98092d500a048d09fd01090bd0d3a4861fc8ea2438bd74a8f43be6f47f02".decode('hex')

cleartext = "SECRET MESSAGE\x02\x02" # okcs #7 padding
iv = "375a12d6de4ef26b735f6fccfbafff2d".decode('hex')
aes = AES.new(encryption_key, AES.MODE_CBC, iv)
c = "c1c82acc436de625edf7feca3c9deb4c".decode('hex')
cn = aes.encrypt(cleartext)
assert cn == c

aes = AES.new(encryption_key, AES.MODE_CBC, iv)
print(aes.decrypt(c).encode('hex'))
cb64 = c.encode('base64').strip()
print(cb64)

local_hash = HMAC.new(hmac_key, digestmod=SHA256)
local_hash.update(cb64)
local_digest = local_hash.hexdigest()
assert local_digest == "b5d1479ae2019663d6572b8e8a734e5f06c1602a0cd0becb87ca81501a08fa55"

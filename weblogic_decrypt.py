#!/usr/bin/env python3
"""
Usage:
  python3 weblogic_decrypt.py -i /path/to/SerializedSystemIni.dat -s "{AES}jNdVLr...="
  python3 weblogic_decrypt.py -i /path/to/SerializedSystemIni.dat -f /path/to/config.xml
"""
from Cryptodome.Cipher import ARC2, AES, DES3
from Cryptodome.Hash import SHA
from base64 import b64decode
import struct, os, functools
from optparse import OptionParser
import re

# helpers
def unpad(s):
    return s[0:-s[-1]]

def ceildiv(n, d):
    return (n + d - 1) // d

# constant used by WebLogic implementations
WEBLOGIC_MASTER_KEY = "0xccb97558940b82637c8bec3c770f86fa3a391a56"

def unpack_helper(fmt, data):
    size = struct.calcsize(fmt)
    return struct.unpack(fmt, data[:size]), data[size:]

def PBKDF3(P, S, count, dklen, ivlen, hashmod):
    def makelen(b, tolen):
        q, r = divmod(tolen, len(b)) if b else (0, 0)
        return b * q + b[:r]
    u = hashmod.digest_size
    v = hashmod.block_size
    S = makelen(S, v * ceildiv(len(S), v))
    P = makelen(P, v * ceildiv(len(P), v))
    II = S + P

    def kdf(xlen, identifier, input_block):
        k = ceildiv(xlen, u)
        D = (chr(identifier) * v).encode('utf-8')
        A = []
        for _ in range(1, k + 1):
            Ai = functools.reduce(lambda a, __: hashmod.new(a).digest(), range(count), D + input_block)
            A.append(Ai)
            # note: this loop mirrors behavior in referenced implementations
        return b''.join(A)[:xlen], input_block

    key, input_block = kdf(dklen, 1, II)
    init, input_block = (kdf(ivlen, 2, input_block) if ivlen > 1 else (None, input_block))
    return key, init

def read_ini_file(path):
    with open(path, 'rb') as fd:
        b = fd.read()
    (salt_len,), b = unpack_helper("=B", b)
    (salt, version, key_len), b = unpack_helper("=%ssBB" % salt_len, b)
    (key,), b = unpack_helper("=%ss" % key_len, b)
    if version >= 2:
        (key_len,), b = unpack_helper("=B", b)
        (key,), b = unpack_helper("=%ss" % key_len, b)
    return (salt, key)

def decrypt_pbe_with_and_128rc2_CBC(cipher_text, password, salt, count):
    kdf = PBKDF3(password, salt, count, 16, 8, SHA)
    cipher = ARC2.new(kdf[0], ARC2.MODE_CBC, kdf[1], effective_keylen=128)
    secret_key = unpad(cipher.decrypt(cipher_text))
    return secret_key

def decrypt_AES(key, data, salt):
    # data: iv + ciphertext (we assume iv is first AES.block_size bytes)
    iv = data[:AES.block_size]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plain = unpad(cipher.decrypt(data[AES.block_size:]))
    return plain

def decrypt_3DES(key, data, salt):
    iv = salt[DES3.block_size:DES3.block_size*2] if len(salt) >= DES3.block_size*2 else salt[:DES3.block_size]
    cipher = DES3.new(key, DES3.MODE_CBC, iv)
    plain = cipher.decrypt(data)
    # 3DES may not use PKCS#7 unpad in some versions; attempt to unpad safely
    try:
        return unpad(plain)
    except Exception:
        return plain

def main():
    parser = OptionParser(usage="%prog [options]")
    parser.add_option("-i", "--ini", dest="ini_file", help="Path to SerializedSystemIni.dat", default='./SerializedSystemIni.dat')
    parser.add_option("-s", "--string", dest="cipher_string", help='Cipher string like "{AES}...." or "{3DES}...."')
    parser.add_option("-f", "--config-file", dest="config_file", help="Optional config file to scan for encrypted strings (e.g. config.xml)")

    (options, args) = parser.parse_args()
    if not options.ini_file or not os.path.isfile(options.ini_file):
        parser.error('Missing or invalid SerializedSystemIni.dat file')

    datas = []
    if options.cipher_string:
        if 'AES' in options.cipher_string:
            datas = [(decrypt_AES, None, options.cipher_string.split('}')[1])]
        elif options.cipher_string.startswith('{3DES}'):
            datas = [(decrypt_3DES, None, options.cipher_string.split('}')[1])]
        else:
            parser.error('Cipher string needs to include AES or 3DES')
    elif options.config_file:
        if not os.path.isfile(options.config_file):
            parser.error('Config file does not exist')
        with open(options.config_file, 'r', encoding='utf-8', errors='ignore') as fd:
            for line in fd:
                if '{AES' in line or '{3DES' in line:
                    if "=" in line:
                        if '{AES' in line:
                            aes_value = re.search(r'\{AES[0-9]*\}([A-Za-z0-9+/=]+)', line).group(1)
                            datas.append((decrypt_AES, None, aes_value))
                        else:
                            des_value = re.search(r'\{3DES[0-9]*\}([A-Za-z0-9+/=]+)', line).group(1)
                            datas.append((decrypt_3DES, None, des_value))
        if len(datas) == 0:
            parser.error('No password found in the config file')
    else:
        parser.error('Provide either -s/--string or -f/--config-file')

    # Java utf-16-be encoding of master key + null
    password = (WEBLOGIC_MASTER_KEY + u'\0').encode('utf-16-be')

    salt, encryption_key = read_ini_file(options.ini_file)

    # decrypt the PBE-encrypted "encryption_key" using PBEWITHSHAAND128BITRC2-CBC with 5 rounds
    secret_key = decrypt_pbe_with_and_128rc2_CBC(encryption_key, password, salt, 5)

    for decrypt_fn, name, ciphertext in datas:
        data = b64decode(ciphertext)
        plain = decrypt_fn(secret_key, data, salt)
        if name:
            print(f"[+] {name}: {plain.decode(errors='replace')}")
        else:
            print(f"[+] Password: {plain.decode(errors='replace')}")

if __name__ == "__main__":
    main()

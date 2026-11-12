#!/usr/bin/env python3
"""
Shifu — CLI шифровальщик любых файлов.

Использование:
    shifu encrypt <файл> [-k <файл ключа>] [--shamir K/N] [-r <публичный ключ>] [-o <папка>]
    shifu decrypt <файл.shifu> [-p <файл пароля>] [-k <файл ключа>]... [-o <папка>]
    shifu keygen [-o <папка>]
    shifu hide <файл> -c <носитель> [--decoy <файл>] [-k <файл ключа>] [-o <носитель>]
    shifu reveal <носитель> [-p <файл пароля>] [-k <файл ключа>] [-o <папка>]

Зависимости:
    pip install colorama cryptography>=45.0 argon2-cffi pillow
"""

import os
import sys
import argparse
import secrets
import string
import hashlib
import struct
import glob
import wave
import tempfile

from argon2.low_level import Type, hash_secret_raw
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from colorama import init as colorama_init, Fore, Style

MAGIC_V1 = b"SHIFU1"
MAGIC_V2 = b"SHIFU2"
MAGIC_V3 = b"SHIFU3"
MAGIC_V4 = b"SHIFU4"
GCM_TAG_LEN = 16  # размер тега AEAD, добавляемый каждым слоем к каждому блоку
PASSWORD_LEN = 50
CHUNK_SIZE = 64 * 1024
SALT_LEN = 32
NONCE_PREFIX_LEN = 4
NONCE_LEN = 12
KEYFILE_LEN = 32
V2_HEADER_LEN = len(MAGIC_V2) + 1 + 4 + 1 + SALT_LEN + NONCE_PREFIX_LEN + 8
V3_HEADER_LEN = len(MAGIC_V3) + 1 + 4 + 1 + 2 * SALT_LEN + 2 * NONCE_PREFIX_LEN + 8
V4_HEADER_LEN = len(MAGIC_V4) + 1 + 4 + 1 + 2 * SALT_LEN + 2 * NONCE_PREFIX_LEN + 8
ARGON2_TIME_COST = 4
ARGON2_MEMORY_COST = 524_288
ARGON2_PARALLELISM = 1
MAX_TIME_COST = 16
MAX_PARALLELISM = 16
MAX_MEMORY_COST = 1_048_576
PBKDF2_V1_ITERATIONS = 200_000
V1_STATIC_SALT = b"shifu-static-salt"
INFO_KEYFILE = b"shifu4/keyfile"
INFO_AES = b"shifu4/aes"
INFO_CHACHA = b"shifu4/chacha"
DECOY_KEYFILE = b"shifu4/decoy"
MAGIC_V5 = b"SHIFU5"
V5_MODE_SHAMIR = 1
V5_MODE_KEM = 2
V5_HEADER_BASE = len(MAGIC_V5) + 1 + 1 + 4 + 1 + 2 * SALT_LEN + 2 * NONCE_PREFIX_LEN + 8
V5_SHAMIR_EXTRA = 2 + 8
V5_KEM_CT_LEN = 1568
V5_KEM_EPH_XPK_LEN = 32
V5_KEM_EXTRA = V5_KEM_CT_LEN + V5_KEM_EPH_XPK_LEN
INFO_KEM = b"shifu5/kem"
MLKEM_EK_LEN = 1568
MLKEM_SEED_LEN = 64
X25519_KEY_LEN = 32
PUB_MAGIC = b"SHIFU5PUB"
PRV_MAGIC = b"SHIFU5PRV"
PUB_FILE_LEN = len(PUB_MAGIC) + 1 + MLKEM_EK_LEN + X25519_KEY_LEN
PRV_FILE_LEN = len(PRV_MAGIC) + 1 + MLKEM_SEED_LEN + X25519_KEY_LEN
SHARE_MAGIC = b"SHF5SHR"
SHARE_FILE_LEN = len(SHARE_MAGIC) + 1 + 8 + 3 + KEYFILE_LEN

colorama_init()

LOGO_LINES = [
    r"  _____ _     _       _____ ___  __  __ ",
    r" / ____| |   (_)     |____  |__ \|  \/  |",
    r"| (___ | |__  _  ___     / /    ) | \  / |",
    r" \___ \| '_ \| |/ _ \   / /    / /_| |  | |",
    r" ____) | | | | |  __/  / /    / /_| |  | |",
    r"|_____/|_| |_|_|\___| /_/   |_____|_|  |_|",
]


def print_logo():
    for line in LOGO_LINES:
        half = len(line) // 2
        print(Fore.RED + line[:half] + Style.RESET_ALL + line[half:])
    print(Style.RESET_ALL)


# ---------- Криптография ----------

def generate_password(length: int = PASSWORD_LEN) -> str:
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*()-_=+"
    return "".join(secrets.choice(alphabet) for _ in range(length))


def derive_key(password: str, salt: bytes, time_cost: int, memory_cost: int, parallelism: int) -> bytes:
    return hash_secret_raw(
        secret=password.encode(),
        salt=salt,
        time_cost=time_cost,
        memory_cost=memory_cost,
        parallelism=parallelism,
        hash_len=32,
        type=Type.ID,
    )


def derive_key_v1(password: str) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", password.encode(), V1_STATIC_SALT, PBKDF2_V1_ITERATIONS)


def hkdf32(ikm: bytes, salt: bytes, info: bytes) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=info).derive(ikm)


def resolve_out_dir(out_dir, src_path: str) -> str:
    if out_dir is None:
        return os.path.dirname(os.path.abspath(src_path))
    os.makedirs(out_dir, exist_ok=True)
    return os.path.abspath(out_dir)


def _cascade_encrypt(src: str, dst: str, header: bytes, nonce_prefix1: bytes, nonce_prefix2: bytes, kek1: bytes, kek2: bytes, salt1: bytes, salt2: bytes, real_length: int, padded_length: int):
    ikm = kek1 + kek2
    layer1 = AESGCM(hkdf32(ikm, salt1, INFO_AES))
    layer2 = ChaCha20Poly1305(hkdf32(ikm, salt2, INFO_CHACHA))
    with open(src, "rb") as src_f, open(dst, "wb", buffering=0) as out:
        out.write(header)
        remaining = padded_length
        pending = struct.pack(">Q", real_length)
        chunk_index = 0
        while remaining > 0:
            take = min(CHUNK_SIZE, remaining)
            buf = pending
            if len(buf) < take:
                data = src_f.read(take - len(buf))
                buf += data + b"\x00" * (take - len(buf) - len(data))
            aad = header + struct.pack(">Q", out.tell())
            nonce1 = nonce_prefix1 + struct.pack(">Q", chunk_index)
            nonce2 = nonce_prefix2 + struct.pack(">Q", chunk_index)
            out.write(layer2.encrypt(nonce2, layer1.encrypt(nonce1, buf, aad), aad))
            remaining -= take
            pending = b""
            chunk_index += 1


def encrypt_file(src: str, password: str, keyfile_bytes: bytes, dst: str):
    salt1 = secrets.token_bytes(SALT_LEN)
    salt2 = secrets.token_bytes(SALT_LEN)
    nonce_prefix1 = secrets.token_bytes(NONCE_PREFIX_LEN)
    nonce_prefix2 = secrets.token_bytes(NONCE_PREFIX_LEN)
    real_length = os.path.getsize(src)
    stream_length = real_length + 8
    padded_length = ((stream_length + CHUNK_SIZE - 1) // CHUNK_SIZE) * CHUNK_SIZE
    header = (
        MAGIC_V4
        + bytes([ARGON2_TIME_COST])
        + struct.pack(">I", ARGON2_MEMORY_COST)
        + bytes([ARGON2_PARALLELISM])
        + salt1
        + salt2
        + nonce_prefix1
        + nonce_prefix2
        + struct.pack(">Q", padded_length)
    )
    kek1 = derive_key(password, salt1, ARGON2_TIME_COST, ARGON2_MEMORY_COST, ARGON2_PARALLELISM)
    kek2 = hkdf32(keyfile_bytes, salt2, INFO_KEYFILE)
    _cascade_encrypt(src, dst, header, nonce_prefix1, nonce_prefix2, kek1, kek2, salt1, salt2, real_length, padded_length)


def encrypt_file_v5(src: str, password: str, dst: str, mode: int, extra_builder):
    salt1 = secrets.token_bytes(SALT_LEN)
    salt2 = secrets.token_bytes(SALT_LEN)
    nonce_prefix1 = secrets.token_bytes(NONCE_PREFIX_LEN)
    nonce_prefix2 = secrets.token_bytes(NONCE_PREFIX_LEN)
    real_length = os.path.getsize(src)
    stream_length = real_length + 8
    padded_length = ((stream_length + CHUNK_SIZE - 1) // CHUNK_SIZE) * CHUNK_SIZE
    kek1 = derive_key(password, salt1, ARGON2_TIME_COST, ARGON2_MEMORY_COST, ARGON2_PARALLELISM)
    kek2, extra = extra_builder(salt2)
    header = (
        MAGIC_V5
        + bytes([mode])
        + bytes([ARGON2_TIME_COST])
        + struct.pack(">I", ARGON2_MEMORY_COST)
        + bytes([ARGON2_PARALLELISM])
        + salt1
        + salt2
        + nonce_prefix1
        + nonce_prefix2
        + struct.pack(">Q", padded_length)
        + extra
    )
    _cascade_encrypt(src, dst, header, nonce_prefix1, nonce_prefix2, kek1, kek2, salt1, salt2, real_length, padded_length)


def decrypt_file(src: str, password: str, dst: str, keyfile_bytes: bytes = None):
    with open(src, "rb") as src_f:
        head = src_f.read(len(MAGIC_V4))
        if head == MAGIC_V1:
            decrypt_file_v1(src_f, password, dst)
            return
        if head == MAGIC_V2:
            decrypt_file_v2(src_f, password, dst)
            return
        if head == MAGIC_V3:
            decrypt_file_v3(src_f, password, dst)
            return
        if head == MAGIC_V5:
            raise ValueError("для формата v5 укажите доли ключа или приватный ключ (-k)")
        if head != MAGIC_V4:
            raise ValueError("неизвестный формат файла")
        if keyfile_bytes is None:
            raise ValueError("для формата v4 требуется файл ключа (-k)")
        decrypt_file_v4(src_f, password, keyfile_bytes, dst)


def _parse_kdf_header(header: bytes, offset: int):
    time_cost = header[offset]
    memory_cost = struct.unpack(">I", header[offset + 1:offset + 5])[0]
    parallelism = header[offset + 5]
    if not (
        1 <= time_cost <= MAX_TIME_COST
        and 1 <= parallelism <= MAX_PARALLELISM
        and 8 * parallelism <= memory_cost <= MAX_MEMORY_COST
    ):
        raise ValueError("недопустимые параметры KDF")
    base = offset + 6
    salt1 = header[base:base + SALT_LEN]
    salt2 = header[base + SALT_LEN:base + 2 * SALT_LEN]
    nonce_prefix1 = header[base + 2 * SALT_LEN:base + 2 * SALT_LEN + NONCE_PREFIX_LEN]
    nonce_prefix2 = header[base + 2 * SALT_LEN + NONCE_PREFIX_LEN:base + 2 * SALT_LEN + 2 * NONCE_PREFIX_LEN]
    padded_length = struct.unpack(">Q", header[base + 2 * SALT_LEN + 2 * NONCE_PREFIX_LEN:base + 2 * SALT_LEN + 2 * NONCE_PREFIX_LEN + 8])[0]
    return time_cost, memory_cost, parallelism, salt1, salt2, nonce_prefix1, nonce_prefix2, padded_length


def _cascade_decrypt(src_f, header: bytes, header_len: int, padded_length: int, nonce_prefix1: bytes, nonce_prefix2: bytes, kek1: bytes, kek2: bytes, salt1: bytes, salt2: bytes, dst: str):
    if padded_length == 0 or padded_length % CHUNK_SIZE != 0:
        raise ValueError("файл повреждён")
    chunks = padded_length // CHUNK_SIZE
    expected_size = header_len + chunks * (CHUNK_SIZE + 2 * GCM_TAG_LEN)
    if os.fstat(src_f.fileno()).st_size != expected_size:
        raise ValueError("файл повреждён или усечён")
    ikm = kek1 + kek2
    layer1 = AESGCM(hkdf32(ikm, salt1, INFO_AES))
    layer2 = ChaCha20Poly1305(hkdf32(ikm, salt2, INFO_CHACHA))

    def blocks():
        chunk_index = 0
        while chunk_index < chunks:
            offset = src_f.tell()
            chunk = src_f.read(CHUNK_SIZE + 2 * GCM_TAG_LEN)
            if len(chunk) != CHUNK_SIZE + 2 * GCM_TAG_LEN:
                raise ValueError("файл повреждён")
            aad = header + struct.pack(">Q", offset)
            nonce1 = nonce_prefix1 + struct.pack(">Q", chunk_index)
            nonce2 = nonce_prefix2 + struct.pack(">Q", chunk_index)
            yield layer1.decrypt(nonce1, layer2.decrypt(nonce2, chunk, aad), aad)
            chunk_index += 1

    src_f.seek(header_len)
    try:
        for _ in blocks():
            pass
    except InvalidTag:
        raise ValueError("неверный пароль, ключ или файл повреждён") from None
    src_f.seek(header_len)
    try:
        with open(dst, "wb", buffering=0) as out:
            real_length = None
            for block in blocks():
                if real_length is None:
                    real_length = struct.unpack(">Q", block[:8])[0]
                    if real_length > padded_length - 8:
                        raise ValueError("файл повреждён")
                    out.write(block[8:])
                else:
                    out.write(block)
            out.truncate(real_length)
    except InvalidTag:
        raise ValueError("неверный пароль, ключ или файл повреждён") from None


def decrypt_file_v4(src_f, password: str, keyfile_bytes: bytes, dst: str):
    rest = src_f.read(V4_HEADER_LEN - len(MAGIC_V4))
    if len(rest) != V4_HEADER_LEN - len(MAGIC_V4):
        raise ValueError("файл повреждён")
    header = MAGIC_V4 + rest
    time_cost, memory_cost, parallelism, salt1, salt2, nonce_prefix1, nonce_prefix2, padded_length = _parse_kdf_header(header, 6)
    kek1 = derive_key(password, salt1, time_cost, memory_cost, parallelism)
    kek2 = hkdf32(keyfile_bytes, salt2, INFO_KEYFILE)
    _cascade_decrypt(src_f, header, V4_HEADER_LEN, padded_length, nonce_prefix1, nonce_prefix2, kek1, kek2, salt1, salt2, dst)


def read_v5_header(f):
    head = f.read(V5_HEADER_BASE)
    if len(head) != V5_HEADER_BASE or head[:6] != MAGIC_V5:
        raise ValueError("файл повреждён или не является форматом v5")
    mode = head[6]
    if mode == V5_MODE_SHAMIR:
        extra_len = V5_SHAMIR_EXTRA
    elif mode == V5_MODE_KEM:
        extra_len = V5_KEM_EXTRA
    else:
        raise ValueError("неизвестный режим формата v5")
    extra = f.read(extra_len)
    if len(extra) != extra_len:
        raise ValueError("файл повреждён")
    if mode == V5_MODE_SHAMIR:
        k, n = extra[0], extra[1]
        if not (1 <= k <= n <= 255):
            raise ValueError("недопустимые параметры схемы Шамира")
    return mode, extra, head + extra


def decrypt_file_v5(src: str, password: str, dst: str, factor2):
    with open(src, "rb") as src_f:
        _mode, _extra, header = read_v5_header(src_f)
        time_cost, memory_cost, parallelism, salt1, salt2, nonce_prefix1, nonce_prefix2, padded_length = _parse_kdf_header(header, 7)
        kek1 = derive_key(password, salt1, time_cost, memory_cost, parallelism)
        kek2 = factor2(salt2)
        _cascade_decrypt(src_f, header, len(header), padded_length, nonce_prefix1, nonce_prefix2, kek1, kek2, salt1, salt2, dst)


def decrypt_file_v3(src_f, password: str, dst: str):
    rest = src_f.read(V3_HEADER_LEN - len(MAGIC_V3))
    if len(rest) != V3_HEADER_LEN - len(MAGIC_V3):
        raise ValueError("файл повреждён")
    header = MAGIC_V3 + rest
    time_cost = header[6]
    memory_cost = struct.unpack(">I", header[7:11])[0]
    parallelism = header[11]
    if not (
        1 <= time_cost <= MAX_TIME_COST
        and 1 <= parallelism <= MAX_PARALLELISM
        and 8 * parallelism <= memory_cost <= MAX_MEMORY_COST
    ):
        raise ValueError("недопустимые параметры KDF")
    salt1 = header[12:12 + SALT_LEN]
    salt2 = header[12 + SALT_LEN:12 + 2 * SALT_LEN]
    nonce_prefix1 = header[12 + 2 * SALT_LEN:12 + 2 * SALT_LEN + NONCE_PREFIX_LEN]
    nonce_prefix2 = header[12 + 2 * SALT_LEN + NONCE_PREFIX_LEN:12 + 2 * SALT_LEN + 2 * NONCE_PREFIX_LEN]
    length = struct.unpack(">Q", header[12 + 2 * SALT_LEN + 2 * NONCE_PREFIX_LEN:])[0]
    chunks, tail = divmod(length, CHUNK_SIZE)
    expected_size = V3_HEADER_LEN + chunks * (CHUNK_SIZE + 2 * GCM_TAG_LEN)
    if tail:
        expected_size += tail + 2 * GCM_TAG_LEN
    if os.fstat(src_f.fileno()).st_size != expected_size:
        raise ValueError("файл повреждён или усечён")
    layer1 = AESGCM(derive_key(password, salt1, time_cost, memory_cost, parallelism))
    layer2 = ChaCha20Poly1305(derive_key(password, salt2, time_cost, memory_cost, parallelism))

    def blocks():
        chunk_index = 0
        while True:
            offset = src_f.tell()
            chunk = src_f.read(CHUNK_SIZE + 2 * GCM_TAG_LEN)
            if not chunk:
                return
            aad = header + struct.pack(">Q", offset)
            nonce1 = nonce_prefix1 + struct.pack(">Q", chunk_index)
            nonce2 = nonce_prefix2 + struct.pack(">Q", chunk_index)
            yield layer1.decrypt(nonce1, layer2.decrypt(nonce2, chunk, aad), aad)
            chunk_index += 1

    src_f.seek(V3_HEADER_LEN)
    try:
        for _ in blocks():
            pass
    except InvalidTag:
        raise ValueError("неверный пароль или файл повреждён") from None
    src_f.seek(V3_HEADER_LEN)
    try:
        with open(dst, "wb", buffering=0) as out:
            for block in blocks():
                out.write(block)
    except InvalidTag:
        raise ValueError("неверный пароль или файл повреждён") from None


def decrypt_file_v2(src_f, password: str, dst: str):
    rest = src_f.read(V2_HEADER_LEN - len(MAGIC_V2))
    if len(rest) != V2_HEADER_LEN - len(MAGIC_V2):
        raise ValueError("файл повреждён")
    header = MAGIC_V2 + rest
    time_cost = header[6]
    memory_cost = struct.unpack(">I", header[7:11])[0]
    parallelism = header[11]
    if not (
        1 <= time_cost <= MAX_TIME_COST
        and 1 <= parallelism <= MAX_PARALLELISM
        and 8 * parallelism <= memory_cost <= MAX_MEMORY_COST
    ):
        raise ValueError("недопустимые параметры KDF")
    salt = header[12:12 + SALT_LEN]
    nonce_prefix = header[12 + SALT_LEN:12 + SALT_LEN + NONCE_PREFIX_LEN]
    length = struct.unpack(">Q", header[12 + SALT_LEN + NONCE_PREFIX_LEN:])[0]
    chunks, tail = divmod(length, CHUNK_SIZE)
    expected_size = V2_HEADER_LEN + chunks * (CHUNK_SIZE + GCM_TAG_LEN)
    if tail:
        expected_size += tail + GCM_TAG_LEN
    if os.fstat(src_f.fileno()).st_size != expected_size:
        raise ValueError("файл повреждён или усечён")
    aes = AESGCM(derive_key(password, salt, time_cost, memory_cost, parallelism))

    def blocks():
        chunk_index = 0
        while True:
            offset = src_f.tell()
            chunk = src_f.read(CHUNK_SIZE + GCM_TAG_LEN)
            if not chunk:
                return
            aad = header + struct.pack(">Q", offset)
            nonce = nonce_prefix + struct.pack(">Q", chunk_index)
            yield aes.decrypt(nonce, chunk, aad)
            chunk_index += 1

    src_f.seek(V2_HEADER_LEN)
    try:
        for _ in blocks():
            pass
    except InvalidTag:
        raise ValueError("неверный пароль или файл повреждён") from None
    src_f.seek(V2_HEADER_LEN)
    try:
        with open(dst, "wb", buffering=0) as out:
            for block in blocks():
                out.write(block)
    except InvalidTag:
        raise ValueError("неверный пароль или файл повреждён") from None


def decrypt_file_v1(src_f, password: str, dst: str):
    aes = AESGCM(derive_key_v1(password))
    nonce = src_f.read(NONCE_LEN)
    if len(nonce) != NONCE_LEN:
        raise ValueError("файл повреждён")
    try:
        with open(dst, "wb", buffering=0) as out:
            while True:
                offset = src_f.tell()
                chunk = src_f.read(CHUNK_SIZE + GCM_TAG_LEN)
                if not chunk:
                    break
                out.write(aes.decrypt(nonce, chunk, struct.pack(">Q", offset)))
    except InvalidTag:
        raise ValueError("неверный пароль или файл повреждён") from None


# ---------- v5: Шамир и постквантовый KEM ----------

_GF_EXP = [0] * 510
_GF_LOG = [0] * 256


def _init_gf():
    x = 1
    for i in range(255):
        _GF_EXP[i] = x
        _GF_LOG[x] = i
        x <<= 1
        if x & 0x100:
            x ^= 0x11B
        x ^= _GF_EXP[i]
    for i in range(255, 510):
        _GF_EXP[i] = _GF_EXP[i - 255]


_init_gf()


def _gf_mul(a: int, b: int) -> int:
    if a == 0 or b == 0:
        return 0
    return _GF_EXP[_GF_LOG[a] + _GF_LOG[b]]


def _gf_inv(a: int) -> int:
    if a == 0:
        raise ValueError("дублирующиеся доли ключа")
    return _GF_EXP[(255 - _GF_LOG[a]) % 255]


def shamir_split(secret: bytes, k: int, n: int):
    if len(secret) != KEYFILE_LEN:
        raise ValueError("недопустимый размер секрета")
    if not (1 <= k <= n <= 255):
        raise ValueError("недопустимые параметры схемы Шамира")
    coeffs = [secret] + [secrets.token_bytes(KEYFILE_LEN) for _ in range(k - 1)]
    shares = []
    for x in range(1, n + 1):
        y = bytearray(KEYFILE_LEN)
        for j in range(KEYFILE_LEN):
            acc = coeffs[k - 1][j]
            for idx in range(k - 2, -1, -1):
                acc = _gf_mul(acc, x) ^ coeffs[idx][j]
            y[j] = acc
        shares.append((x, bytes(y)))
    return shares


def shamir_combine(points) -> bytes:
    if not points:
        raise ValueError("нет долей ключа")
    if len(set(x for x, _ in points)) != len(points):
        raise ValueError("дублирующиеся доли ключа")
    weights = []
    for i, (xi, _) in enumerate(points):
        num = 1
        den = 1
        for m, (xm, _) in enumerate(points):
            if m == i:
                continue
            num = _gf_mul(num, xm)
            den = _gf_mul(den, xm ^ xi)
        weights.append(_gf_mul(num, _gf_inv(den)))
    secret = bytearray(KEYFILE_LEN)
    for (_, y), w in zip(points, weights):
        for j in range(KEYFILE_LEN):
            secret[j] ^= _gf_mul(y[j], w)
    return bytes(secret)


def write_share_file(path: str, uid: bytes, k: int, n: int, x: int, y: bytes):
    blob = SHARE_MAGIC + bytes([1]) + uid + bytes([k, n, x]) + y
    with open(path, "wb") as f:
        f.write(blob)
    os.chmod(path, 0o600)


def read_share_file(path: str):
    with open(path, "rb") as f:
        blob = f.read()
    if len(blob) != SHARE_FILE_LEN or blob[:7] != SHARE_MAGIC or blob[7] != 1 or blob[18] == 0:
        raise ValueError(f"файл не является долей ключа shifu: {path}")
    uid = blob[8:16]
    k, n, x = blob[16], blob[17], blob[18]
    y = blob[19:]
    return uid, k, n, x, y


def _require_mlkem():
    try:
        from cryptography.hazmat.primitives.asymmetric import mlkem
        return mlkem
    except ImportError:
        raise RuntimeError("режим получателя требует cryptography>=45.0: pip install -U cryptography") from None


def load_pub_file(path: str):
    with open(path, "rb") as f:
        blob = f.read()
    if len(blob) != PUB_FILE_LEN or blob[:9] != PUB_MAGIC or blob[9] != 1:
        raise ValueError(f"файл не является публичным ключом shifu5: {path}")
    return blob[10:10 + MLKEM_EK_LEN], blob[10 + MLKEM_EK_LEN:]


def load_priv_file(path: str):
    with open(path, "rb") as f:
        blob = f.read()
    if len(blob) != PRV_FILE_LEN or blob[:9] != PRV_MAGIC or blob[9] != 1:
        raise ValueError(f"файл не является приватным ключом shifu5: {path}")
    return blob[10:10 + MLKEM_SEED_LEN], blob[10 + MLKEM_SEED_LEN:]


def kem_extra_builder(ek: bytes, xpk: bytes):
    def build(salt2: bytes):
        mlkem = _require_mlkem()
        from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
        pub = mlkem.MLKEM1024PublicKey.from_public_bytes(ek)
        ss, ct = pub.encapsulate()
        eph = X25519PrivateKey.generate()
        xss = eph.exchange(X25519PublicKey.from_public_bytes(xpk))
        return hkdf32(ss + xss, salt2, INFO_KEM), ct + eph.public_key().public_bytes_raw()
    return build


def resolve_kem_kek2(priv_path: str, extra: bytes, salt2: bytes) -> bytes:
    mlkem = _require_mlkem()
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
    ct = extra[:V5_KEM_CT_LEN]
    ephpk = extra[V5_KEM_CT_LEN:]
    if len(ephpk) != V5_KEM_EPH_XPK_LEN:
        raise ValueError("файл повреждён")
    seed, xsk = load_priv_file(priv_path)
    try:
        sk = mlkem.MLKEM1024PrivateKey.from_seed_bytes(seed)
        ss = sk.decapsulate(ct)
    except ValueError:
        raise ValueError("приватный ключ повреждён или не соответствует получателю") from None
    xss = X25519PrivateKey.from_private_bytes(xsk).exchange(X25519PublicKey.from_public_bytes(ephpk))
    return hkdf32(ss + xss, salt2, INFO_KEM)


# ---------- Стеганография ----------

def _lsb_embed(samples, payload: bytes):
    stream = struct.pack(">Q", len(payload)) + payload
    need = len(stream) * 8
    if need > len(samples):
        raise ValueError(f"носитель слишком мал: нужно {need} бит, доступно {len(samples)}")
    bit_index = 0
    for byte in stream:
        for shift in (7, 6, 5, 4, 3, 2, 1, 0):
            samples[bit_index] = (samples[bit_index] & ~1) | ((byte >> shift) & 1)
            bit_index += 1


def _lsb_extract(bit_iter, capacity_bits: int) -> bytes:
    acc = 0
    nbits = 0
    out = bytearray()
    length = None
    for bit in bit_iter:
        acc = (acc << 1) | bit
        nbits += 1
        if nbits < 8:
            continue
        if length is None:
            out.append(acc)
            if len(out) == 8:
                length = struct.unpack(">Q", bytes(out))[0]
                if length <= 0 or length + 8 > capacity_bits // 8:
                    raise ValueError("в носителе нет данных shifu")
                out = bytearray()
        else:
            out.append(acc)
            if len(out) == length:
                return bytes(out)
        acc = 0
        nbits = 0
    raise ValueError("в носителе нет данных shifu")


def _require_pillow():
    try:
        from PIL import Image
    except ImportError:
        raise RuntimeError("для работы с изображениями установите pillow: pip install pillow")
    return Image


def _embed_image(carrier_path: str, payload: bytes, out_path: str):
    Image = _require_pillow()
    img = Image.open(carrier_path)
    if img.mode not in ("L", "RGB", "RGBA", "LA"):
        img = img.convert("RGBA" if "transparency" in img.info else "RGB")
    data = list(img.getdata())
    is_tuple = isinstance(data[0], tuple)
    if is_tuple:
        flat = [v for pixel in data for v in pixel]
    else:
        flat = data
    _lsb_embed(flat, payload)
    if is_tuple:
        channels = len(data[0])
        it = iter(flat)
        data = [tuple(next(it) for _ in range(channels)) for _ in range(len(data))]
    else:
        data = flat
    img.putdata(data)
    img.save(out_path, format="PNG")


def _extract_image(carrier_path: str) -> bytes:
    Image = _require_pillow()
    img = Image.open(carrier_path)
    data = list(img.getdata())
    is_tuple = isinstance(data[0], tuple)
    if is_tuple:
        bit_iter = (v & 1 for pixel in data for v in pixel)
        capacity = len(data) * len(data[0])
    else:
        bit_iter = (v & 1 for v in data)
        capacity = len(data)
    return _lsb_extract(bit_iter, capacity)


def _embed_wav(carrier_path: str, payload: bytes, out_path: str):
    with wave.open(carrier_path, "rb") as w:
        params = w.getparams()
        frames = w.readframes(w.getnframes())
    if params.sampwidth == 2:
        fmt = "<%dh" % (len(frames) // 2)
        samples = list(struct.unpack(fmt, frames))
    elif params.sampwidth == 1:
        samples = list(frames)
    else:
        raise ValueError("поддерживаются только WAV 8 или 16 бит")
    _lsb_embed(samples, payload)
    if params.sampwidth == 2:
        frames = struct.pack(fmt, *samples)
    else:
        frames = bytes(samples)
    with wave.open(out_path, "wb") as w:
        w.setparams(params)
        w.writeframes(frames)


def _extract_wav(carrier_path: str) -> bytes:
    with wave.open(carrier_path, "rb") as w:
        params = w.getparams()
        frames = w.readframes(w.getnframes())
    if params.sampwidth == 2:
        samples = struct.unpack("<%dh" % (len(frames) // 2), frames)
    elif params.sampwidth == 1:
        samples = frames
    else:
        raise ValueError("поддерживаются только WAV 8 или 16 бит")
    return _lsb_extract((s & 1 for s in samples), len(samples))


def _embed_carrier(carrier_path: str, payload: bytes, out_path: str):
    if carrier_path.lower().endswith(".wav"):
        _embed_wav(carrier_path, payload, out_path)
    else:
        _embed_image(carrier_path, payload, out_path)


def _extract_carrier(carrier_path: str) -> bytes:
    if carrier_path.lower().endswith(".wav"):
        return _extract_wav(carrier_path)
    return _extract_image(carrier_path)


# ---------- CLI ----------

def cmd_encrypt(args) -> int:
    shamir = None
    if args.shamir is not None:
        parts = args.shamir.split("/")
        if len(parts) != 2 or not parts[0].isdigit() or not parts[1].isdigit():
            print(f"{Fore.RED}Ошибка: --shamir задаётся как K/N, например 3/5{Style.RESET_ALL}")
            return 1
        k, n = int(parts[0]), int(parts[1])
        if not (1 <= k <= n <= 255):
            print(f"{Fore.RED}Ошибка: требуется 1 <= K <= N <= 255{Style.RESET_ALL}")
            return 1
        shamir = (k, n)
    if shamir is not None and args.recipient is not None:
        print(f"{Fore.RED}Ошибка: --shamir и --recipient нельзя использовать вместе{Style.RESET_ALL}")
        return 1
    if not os.path.isfile(args.file):
        print(f"{Fore.RED}Ошибка: файл не найден: {args.file}{Style.RESET_ALL}")
        return 1

    out_dir = resolve_out_dir(args.out, args.file)
    base = os.path.basename(args.file)
    enc_path = os.path.join(out_dir, base + ".shifu")
    pass_path = os.path.join(out_dir, base + ".shifu.pass")

    keyfile_bytes = None
    if args.keyfile is not None:
        if not os.path.isfile(args.keyfile):
            print(f"{Fore.RED}Ошибка: файл ключа не найден: {args.keyfile}{Style.RESET_ALL}")
            return 1
        with open(args.keyfile, "rb") as kf:
            keyfile_bytes = kf.read()

    if shamir is not None:
        k, n = shamir
        if keyfile_bytes is None:
            keyfile_bytes = secrets.token_bytes(KEYFILE_LEN)
        uid = secrets.token_bytes(8)
        shares = shamir_split(keyfile_bytes, k, n)
        password = generate_password()

        def builder(salt2):
            return hkdf32(keyfile_bytes, salt2, INFO_KEYFILE), bytes([k, n]) + uid

        encrypt_file_v5(args.file, password, enc_path, V5_MODE_SHAMIR, builder)
        with open(pass_path, "w", encoding="utf-8") as pf:
            pf.write(password + "\n")
        os.chmod(pass_path, 0o600)
        print(f"{Fore.GREEN}Готово!{Style.RESET_ALL}")
        print(f"  Зашифрованный файл : {enc_path}")
        print(f"  Пароль (50 знаков) : {pass_path}")
        if args.keyfile is not None:
            print(f"  Внешний файл ключа : {args.keyfile}")
        print(f"  Схема Шамира : любые {k} из {n} долей, ID {uid.hex()}")
        for x, y in shares:
            share_path = f"{enc_path}.key.share{x:02d}"
            write_share_file(share_path, uid, k, n, x, y)
            print(f"    доля ключа : {share_path}")
        print(f"{Fore.RED}ВАЖНО: для расшифровки нужны любые {k} из {n} долей и пароль. Храните доли на разных носителях!{Style.RESET_ALL}")
        return 0

    if args.recipient is not None:
        if not os.path.isfile(args.recipient):
            print(f"{Fore.RED}Ошибка: файл публичного ключа не найден: {args.recipient}{Style.RESET_ALL}")
            return 1
        try:
            ek, xpk = load_pub_file(args.recipient)
        except ValueError as e:
            print(f"{Fore.RED}Ошибка: {e}{Style.RESET_ALL}")
            return 1
        password = generate_password()
        encrypt_file_v5(args.file, password, enc_path, V5_MODE_KEM, kem_extra_builder(ek, xpk))
        with open(pass_path, "w", encoding="utf-8") as pf:
            pf.write(password + "\n")
        os.chmod(pass_path, 0o600)
        print(f"{Fore.GREEN}Готово!{Style.RESET_ALL}")
        print(f"  Зашифрованный файл : {enc_path}")
        print(f"  Пароль (50 знаков) : {pass_path}")
        print(f"  Публичный ключ получателя : {args.recipient}")
        print(f"{Fore.RED}ВАЖНО: расшифровка только приватным ключом этой пары (-k shifu5.priv) и паролем!{Style.RESET_ALL}")
        return 0

    if keyfile_bytes is not None:
        key_note = f"  Внешний файл ключа : {args.keyfile}"
    else:
        key_path = os.path.join(out_dir, base + ".shifu.key")
        keyfile_bytes = secrets.token_bytes(KEYFILE_LEN)
        with open(key_path, "wb") as kf:
            kf.write(keyfile_bytes)
        os.chmod(key_path, 0o600)
        key_note = f"  Файл ключа (32 байта) : {key_path}"

    password = generate_password()
    encrypt_file(args.file, password, keyfile_bytes, enc_path)

    with open(pass_path, "w", encoding="utf-8") as pf:
        pf.write(password + "\n")
    os.chmod(pass_path, 0o600)

    print(f"{Fore.GREEN}Готово!{Style.RESET_ALL}")
    print(f"  Зашифрованный файл : {enc_path}")
    print(f"  Пароль (50 знаков) : {pass_path}")
    print(key_note)
    print(f"{Fore.RED}ВАЖНО: без пароля И файла ключа восстановить невозможно!{Style.RESET_ALL}")
    return 0


def cmd_decrypt(args) -> int:
    if not os.path.isfile(args.file):
        print(f"{Fore.RED}Ошибка: файл не найден: {args.file}{Style.RESET_ALL}")
        return 1

    with open(args.file, "rb") as mf:
        if mf.read(len(MAGIC_V5)) == MAGIC_V5:
            return cmd_decrypt_v5(args)

    if len(args.keyfiles or []) > 1:
        print(f"{Fore.RED}Ошибка: для этого формата указывается один файл ключа{Style.RESET_ALL}")
        return 1

    keyfile_bytes = None
    if args.keyfiles:
        if not os.path.isfile(args.keyfiles[0]):
            print(f"{Fore.RED}Ошибка: файл ключа не найден: {args.keyfiles[0]}{Style.RESET_ALL}")
            return 1
        with open(args.keyfiles[0], "rb") as kf:
            keyfile_bytes = kf.read()

    pass_path = args.passfile
    if pass_path is None:
        pass_path = (args.file[:-6] if args.file.endswith(".shifu") else args.file) + ".shifu.pass"
        if not os.path.isfile(pass_path):
            pass_path = args.file + ".pass"

    if not os.path.isfile(pass_path):
        print(f"{Fore.RED}Ошибка: файл пароля не найден: {pass_path}{Style.RESET_ALL}")
        return 1

    with open(pass_path, "r", encoding="utf-8") as pf:
        password = pf.read().strip()

    if keyfile_bytes is None:
        key_path = (args.file[:-6] if args.file.endswith(".shifu") else args.file) + ".shifu.key"
        if os.path.isfile(key_path):
            with open(key_path, "rb") as kf:
                keyfile_bytes = kf.read()

    out_dir = resolve_out_dir(args.out, args.file)
    base = os.path.basename(args.file)
    base = base[:-6] if base.endswith(".shifu") else base
    out_path = os.path.join(out_dir, base + ".decrypted")

    try:
        decrypt_file(args.file, password, out_path, keyfile_bytes)
    except Exception as e:
        if os.path.exists(out_path):
            os.remove(out_path)
        # показываем реальную причину вместо общей фразы
        print(f"{Fore.RED}Ошибка расшифровки: {e!r}{Style.RESET_ALL}")
        return 1

    print(f"{Fore.GREEN}Расшифровано: {out_path}{Style.RESET_ALL}")
    return 0


def cmd_decrypt_v5(args) -> int:
    with open(args.file, "rb") as mf:
        mode, extra, _ = read_v5_header(mf)

    pass_path = args.passfile
    if pass_path is None:
        pass_path = (args.file[:-6] if args.file.endswith(".shifu") else args.file) + ".shifu.pass"
        if not os.path.isfile(pass_path):
            pass_path = args.file + ".pass"
    if not os.path.isfile(pass_path):
        print(f"{Fore.RED}Ошибка: файл пароля не найден: {pass_path}{Style.RESET_ALL}")
        return 1
    with open(pass_path, "r", encoding="utf-8") as pf:
        password = pf.read().strip()

    keyfiles = args.keyfiles or []

    if mode == V5_MODE_SHAMIR:
        k, n = extra[0], extra[1]
        uid = extra[2:10]
        share_paths = keyfiles
        if not share_paths:
            stripped = args.file[:-6] if args.file.endswith(".shifu") else args.file
            share_paths = sorted(glob.glob(stripped + ".shifu.key.share*"))
        if not share_paths:
            print(f"{Fore.RED}Ошибка: не найдено ни одной доли ключа (файлы *.shifu.key.share* или -k){Style.RESET_ALL}")
            return 1
        points = []
        for sp in share_paths:
            if not os.path.isfile(sp):
                print(f"{Fore.RED}Ошибка: доля не найдена: {sp}{Style.RESET_ALL}")
                return 1
            try:
                s_uid, s_k, s_n, x, y = read_share_file(sp)
            except ValueError as e:
                print(f"{Fore.RED}Ошибка: {e}{Style.RESET_ALL}")
                return 1
            if s_uid != uid:
                print(f"{Fore.RED}Ошибка: доля {sp} принадлежит другому файлу{Style.RESET_ALL}")
                return 1
            if (s_k, s_n) != (k, n):
                print(f"{Fore.RED}Ошибка: доля {sp} несовместима с параметрами файла{Style.RESET_ALL}")
                return 1
            points.append((x, y))
        if len(points) < k:
            print(f"{Fore.RED}Ошибка: нужно минимум {k} долей, найдено {len(points)}{Style.RESET_ALL}")
            return 1
        keyfile_bytes = shamir_combine(points)

        def factor2(salt2):
            return hkdf32(keyfile_bytes, salt2, INFO_KEYFILE)

    elif mode == V5_MODE_KEM:
        if len(keyfiles) != 1:
            print(f"{Fore.RED}Ошибка: укажите приватный ключ: -k shifu5.priv{Style.RESET_ALL}")
            return 1
        if not os.path.isfile(keyfiles[0]):
            print(f"{Fore.RED}Ошибка: файл приватного ключа не найден: {keyfiles[0]}{Style.RESET_ALL}")
            return 1
        priv_path = keyfiles[0]

        def factor2(salt2):
            return resolve_kem_kek2(priv_path, extra, salt2)

    else:
        print(f"{Fore.RED}Ошибка: неизвестный режим формата v5{Style.RESET_ALL}")
        return 1

    out_dir = resolve_out_dir(args.out, args.file)
    base = os.path.basename(args.file)
    base = base[:-6] if base.endswith(".shifu") else base
    out_path = os.path.join(out_dir, base + ".decrypted")

    try:
        decrypt_file_v5(args.file, password, out_path, factor2)
    except Exception as e:
        if os.path.exists(out_path):
            os.remove(out_path)
        print(f"{Fore.RED}Ошибка расшифровки: {e!r}{Style.RESET_ALL}")
        return 1

    print(f"{Fore.GREEN}Расшифровано: {out_path}{Style.RESET_ALL}")
    return 0


def cmd_hide(args) -> int:
    if not os.path.isfile(args.file):
        print(f"{Fore.RED}Ошибка: файл не найден: {args.file}{Style.RESET_ALL}")
        return 1
    if not os.path.isfile(args.carrier):
        print(f"{Fore.RED}Ошибка: носитель не найден: {args.carrier}{Style.RESET_ALL}")
        return 1
    decoy_bytes = None
    if args.decoy is not None:
        if not os.path.isfile(args.decoy):
            print(f"{Fore.RED}Ошибка: файл приманки не найден: {args.decoy}{Style.RESET_ALL}")
            return 1
        with open(args.decoy, "rb") as f:
            decoy_bytes = f.read()

    if args.out is not None:
        out_carrier = os.path.abspath(args.out)
        parent = os.path.dirname(out_carrier)
        if parent:
            os.makedirs(parent, exist_ok=True)
    elif args.carrier.lower().endswith(".wav"):
        out_carrier = os.path.splitext(args.carrier)[0] + ".hidden.wav"
    else:
        out_carrier = os.path.splitext(args.carrier)[0] + ".hidden.png"

    if args.keyfile is not None:
        if not os.path.isfile(args.keyfile):
            print(f"{Fore.RED}Ошибка: файл ключа не найден: {args.keyfile}{Style.RESET_ALL}")
            return 1
        with open(args.keyfile, "rb") as kf:
            keyfile_bytes = kf.read()
        key_note = f"  Внешний файл ключа : {args.keyfile}"
    else:
        keyfile_bytes = secrets.token_bytes(KEYFILE_LEN)
        key_note = None

    password = generate_password()
    decoy_password = None
    blobs = []
    with tempfile.TemporaryDirectory() as td:
        if decoy_bytes is not None:
            decoy_src = os.path.join(td, "decoy.src")
            with open(decoy_src, "wb") as f:
                f.write(decoy_bytes)
            decoy_password = generate_password()
            decoy_blob_path = os.path.join(td, "decoy.shifu")
            encrypt_file(decoy_src, decoy_password, DECOY_KEYFILE, decoy_blob_path)
            with open(decoy_blob_path, "rb") as f:
                blobs.append(f.read())
        real_blob_path = os.path.join(td, "real.shifu")
        encrypt_file(args.file, password, keyfile_bytes, real_blob_path)
        with open(real_blob_path, "rb") as f:
            blobs.append(f.read())

    stream = b"".join(struct.pack(">Q", len(b)) + b for b in blobs)
    try:
        _embed_carrier(args.carrier, stream, out_carrier)
    except Exception as e:
        print(f"{Fore.RED}Ошибка скрытия: {e!r}{Style.RESET_ALL}")
        return 1

    out_base = os.path.splitext(out_carrier)[0]
    pass_path = out_base + ".shifu.pass"
    with open(pass_path, "w", encoding="utf-8") as pf:
        pf.write(password + "\n")
    os.chmod(pass_path, 0o600)

    print(f"{Fore.GREEN}Готово!{Style.RESET_ALL}")
    print(f"  Носитель с данными : {out_carrier}")
    print(f"  Пароль (50 знаков) : {pass_path}")
    if key_note:
        print(key_note)
    else:
        key_path = out_base + ".shifu.key"
        with open(key_path, "wb") as kf:
            kf.write(keyfile_bytes)
        os.chmod(key_path, 0o600)
        print(f"  Файл ключа (32 байта) : {key_path}")
    if decoy_password is not None:
        decoy_pass_path = out_base + ".shifu.decoy.pass"
        with open(decoy_pass_path, "w", encoding="utf-8") as pf:
            pf.write(decoy_password + "\n")
        os.chmod(decoy_pass_path, 0o600)
        print(f"  Пароль приманки (50 знаков) : {decoy_pass_path}")
    print(f"{Fore.RED}ВАЖНО: без пароля и файла ключа восстановить невозможно! Храните их отдельно от носителя.{Style.RESET_ALL}")
    return 0


def cmd_reveal(args) -> int:
    if not os.path.isfile(args.carrier):
        print(f"{Fore.RED}Ошибка: носитель не найден: {args.carrier}{Style.RESET_ALL}")
        return 1

    try:
        stream = _extract_carrier(args.carrier)
    except Exception as e:
        print(f"{Fore.RED}Ошибка извлечения: {e!r}{Style.RESET_ALL}")
        return 1

    blobs = []
    pos = 0
    while pos < len(stream):
        if pos + 8 > len(stream):
            print(f"{Fore.RED}Ошибка: данные носителя повреждены{Style.RESET_ALL}")
            return 1
        blen = struct.unpack(">Q", stream[pos:pos + 8])[0]
        if blen <= 0 or pos + 8 + blen > len(stream):
            print(f"{Fore.RED}Ошибка: данные носителя повреждены{Style.RESET_ALL}")
            return 1
        blob = stream[pos + 8:pos + 8 + blen]
        if blob[:6] not in (MAGIC_V1, MAGIC_V2, MAGIC_V3, MAGIC_V4):
            print(f"{Fore.RED}Ошибка: в носителе нет данных shifu{Style.RESET_ALL}")
            return 1
        blobs.append(blob)
        pos += 8 + blen

    base = os.path.splitext(args.carrier)[0]
    pass_path = args.passfile
    if pass_path is None:
        for candidate in (base + ".shifu.pass", base + ".shifu.decoy.pass"):
            if os.path.isfile(candidate):
                pass_path = candidate
                break
    if pass_path is None or not os.path.isfile(pass_path):
        print(f"{Fore.RED}Ошибка: файл пароля не найден (укажите -p){Style.RESET_ALL}")
        return 1
    with open(pass_path, "r", encoding="utf-8") as pf:
        password = pf.read().strip()

    keyfile_bytes = None
    if args.keyfile is not None:
        if not os.path.isfile(args.keyfile):
            print(f"{Fore.RED}Ошибка: файл ключа не найден: {args.keyfile}{Style.RESET_ALL}")
            return 1
        with open(args.keyfile, "rb") as kf:
            keyfile_bytes = kf.read()
    else:
        key_path = base + ".shifu.key"
        if os.path.isfile(key_path):
            with open(key_path, "rb") as kf:
                keyfile_bytes = kf.read()

    if keyfile_bytes is not None:
        candidates = [(password, keyfile_bytes), (password, DECOY_KEYFILE)]
    else:
        candidates = [(password, DECOY_KEYFILE)]

    out_dir = resolve_out_dir(args.out, args.carrier)
    out_base = os.path.splitext(os.path.basename(args.carrier))[0]

    found = 0
    with tempfile.TemporaryDirectory() as td:
        for n, blob in enumerate(blobs, 1):
            blob_path = os.path.join(td, f"blob{n}.shifu")
            with open(blob_path, "wb") as f:
                f.write(blob)
            for kf_bytes in candidates:
                out_path = os.path.join(out_dir, out_base + ".decrypted" + ("" if found == 0 else f"-{found + 1}"))
                try:
                    decrypt_file(blob_path, kf_bytes[0], out_path, kf_bytes[1])
                except Exception:
                    if os.path.exists(out_path):
                        os.remove(out_path)
                    continue
                print(f"{Fore.GREEN}Расшифровано: {out_path}{Style.RESET_ALL}")
                found += 1
                break

    if found == 0:
        print(f"{Fore.RED}Ошибка: неверный пароль или ключ — данные не расшифрованы{Style.RESET_ALL}")
        return 1
    return 0


def cmd_keygen(args) -> int:
    mlkem = _require_mlkem()
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
    out_dir = os.path.abspath(args.out) if args.out else os.getcwd()
    os.makedirs(out_dir, exist_ok=True)
    priv_path = os.path.join(out_dir, "shifu5.priv")
    pub_path = os.path.join(out_dir, "shifu5.pub")
    if os.path.exists(priv_path) or os.path.exists(pub_path):
        print(f"{Fore.RED}Ошибка: shifu5.priv или shifu5.pub уже существует в {out_dir}{Style.RESET_ALL}")
        return 1
    sk = mlkem.MLKEM1024PrivateKey.generate()
    x = X25519PrivateKey.generate()
    priv_blob = PRV_MAGIC + bytes([1]) + sk.private_bytes_raw() + x.private_bytes_raw()
    pub_blob = PUB_MAGIC + bytes([1]) + sk.public_key().public_bytes_raw() + x.public_key().public_bytes_raw()
    if len(priv_blob) != PRV_FILE_LEN or len(pub_blob) != PUB_FILE_LEN:
        raise RuntimeError("неожиданный размер ключей ML-KEM")
    with open(priv_path, "wb") as f:
        f.write(priv_blob)
    os.chmod(priv_path, 0o600)
    with open(pub_path, "wb") as f:
        f.write(pub_blob)
    os.chmod(pub_path, 0o644)
    print(f"{Fore.GREEN}Готово!{Style.RESET_ALL}")
    print(f"  Приватный ключ (хранить отдельно!) : {priv_path}")
    print(f"  Публичный ключ (можно свободно передавать) : {pub_path}")
    return 0


def main():
    print_logo()

    parser = argparse.ArgumentParser(prog="shifu", description="Shifu — шифровальщик любых файлов")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_enc = sub.add_parser("encrypt", help="зашифровать файл")
    p_enc.add_argument("file", help="путь к файлу")
    p_enc.add_argument("-k", "--keyfile", default=None, help="файл ключа (по умолчанию — сгенерировать новый)")
    p_enc.add_argument("--shamir", default=None, metavar="K/N", help="разделить ключ по схеме Шамира, например 3/5")
    p_enc.add_argument("-r", "--recipient", default=None, help="публичный ключ получателя shifu5.pub (постквантовый режим)")
    p_enc.add_argument("-o", "--out", default=None, help="папка вывода (по умолчанию — рядом с файлом)")
    p_enc.set_defaults(func=cmd_encrypt)

    p_dec = sub.add_parser("decrypt", help="расшифровать файл .shifu")
    p_dec.add_argument("file", help="путь к файлу .shifu")
    p_dec.add_argument("-p", "--passfile", default=None, help="явный путь к файлу пароля")
    p_dec.add_argument("-k", "--keyfile", action="append", dest="keyfiles", metavar="ФАЙЛ", help="файл ключа; для v5 — доли Шамира (можно несколько раз) или приватный ключ")
    p_dec.add_argument("-o", "--out", default=None, help="папка вывода (по умолчанию — рядом с файлом)")
    p_dec.set_defaults(func=cmd_decrypt)

    p_key = sub.add_parser("keygen", help="создать пару ключей shifu5 (ML-KEM-1024 + X25519)")
    p_key.add_argument("-o", "--out", default=None, help="папка для shifu5.priv и shifu5.pub (по умолчанию — текущая)")
    p_key.set_defaults(func=cmd_keygen)

    p_hide = sub.add_parser("hide", help="спрятать файл в изображении или аудио (стеганография)")
    p_hide.add_argument("file", help="путь к скрываемому файлу")
    p_hide.add_argument("-c", "--carrier", required=True, help="носитель: PNG/JPEG (результат — PNG) или WAV")
    p_hide.add_argument("-k", "--keyfile", default=None, help="файл ключа (по умолчанию — сгенерировать новый)")
    p_hide.add_argument("--decoy", default=None, help="файл-приманка для правдоподобного отрицания")
    p_hide.add_argument("-o", "--out", default=None, help="путь к новому носителю (по умолчанию — рядом с исходным)")
    p_hide.set_defaults(func=cmd_hide)

    p_rev = sub.add_parser("reveal", help="извлечь и расшифровать данные из носителя")
    p_rev.add_argument("carrier", help="путь к носителю")
    p_rev.add_argument("-p", "--passfile", default=None, help="файл пароля (реальный или приманки)")
    p_rev.add_argument("-k", "--keyfile", default=None, help="файл ключа")
    p_rev.add_argument("-o", "--out", default=None, help="папка вывода (по умолчанию — рядом с носителем)")
    p_rev.set_defaults(func=cmd_reveal)

    if len(sys.argv) < 2:
        parser.print_help()
        sys.exit(0)

    args = parser.parse_args()
    sys.exit(args.func(args))


if __name__ == "__main__":
    main()

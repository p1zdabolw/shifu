#!/usr/bin/env python3
"""
Shifu — CLI шифровальщик любых файлов.

Использование:
    shifu encrypt <файл> [-o <папка>]
    shifu decrypt <файл.shifu> [-p <файл пароля>] [-o <папка>]

Зависимости:
    pip install colorama cryptography
"""

import os
import sys
import argparse
import secrets
import string
import hashlib
import struct

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from colorama import init as colorama_init, Fore, Style

MAGIC = b"SHIFU1"
GCM_TAG_LEN = 16  # размер тега AES-GCM, добавляется к каждому блоку
PASSWORD_LEN = 50
CHUNK_SIZE = 64 * 1024

colorama_init()

LOGO_LINES = [
    r"  _____ _     _       _____ ___  __  __ ",
    r" / ____| |   (_)     |____  |__ \|  \/  |",
    r"| (___ | |__  _  ___     / /    ) | \  / |",
    r" \___ \| '_ \| |/ _ \   / /    / /| |\/| |",
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


def derive_key(password: str) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", password.encode(), b"shifu-static-salt", 200_000)


def resolve_out_dir(out_dir, src_path: str) -> str:
    if out_dir is None:
        return os.path.dirname(os.path.abspath(src_path))
    os.makedirs(out_dir, exist_ok=True)
    return os.path.abspath(out_dir)


def encrypt_file(src: str, password: str, dst: str):
    key = derive_key(password)
    aes = AESGCM(key)
    nonce = os.urandom(12)

    with open(src, "rb") as src_f, open(dst, "wb", buffering=0) as out:
        out.write(MAGIC)
        out.write(nonce)
        while True:
            chunk = src_f.read(CHUNK_SIZE)
            if not chunk:
                break
            aad = struct.pack(">Q", out.tell())
            out.write(aes.encrypt(nonce, chunk, aad))


def decrypt_file(src: str, password: str, dst: str):
    key = derive_key(password)
    aes = AESGCM(key)

    with open(src, "rb") as src_f, open(dst, "wb", buffering=0) as out:
        if src_f.read(len(MAGIC)) != MAGIC:
            raise ValueError("bad magic")
        nonce = src_f.read(12)
        while True:
            offset = src_f.tell()
            # блок в шифротексте = CHUNK_SIZE байт исходных + 16 байт GCM-тега
            chunk = src_f.read(CHUNK_SIZE + GCM_TAG_LEN)
            if not chunk:
                break
            aad = struct.pack(">Q", offset)
            out.write(aes.decrypt(nonce, chunk, aad))


# ---------- CLI ----------

def cmd_encrypt(args) -> int:
    if not os.path.isfile(args.file):
        print(f"{Fore.RED}Ошибка: файл не найден: {args.file}{Style.RESET_ALL}")
        return 1

    out_dir = resolve_out_dir(args.out, args.file)
    base = os.path.basename(args.file)
    enc_path = os.path.join(out_dir, base + ".shifu")
    pass_path = os.path.join(out_dir, base + ".shifu.pass")

    password = generate_password()
    encrypt_file(args.file, password, enc_path)

    with open(pass_path, "w", encoding="utf-8") as pf:
        pf.write(password + "\n")
    os.chmod(pass_path, 0o600)

    print(f"{Fore.GREEN}Готово!{Style.RESET_ALL}")
    print(f"  Зашифрованный файл : {enc_path}")
    print(f"  Пароль (50 знаков) : {pass_path}")
    print(f"{Fore.RED}ВАЖНО: без пароля файл восстановить невозможно!{Style.RESET_ALL}")
    return 0


def cmd_decrypt(args) -> int:
    if not os.path.isfile(args.file):
        print(f"{Fore.RED}Ошибка: файл не найден: {args.file}{Style.RESET_ALL}")
        return 1

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

    out_dir = resolve_out_dir(args.out, args.file)
    base = os.path.basename(args.file)
    base = base[:-6] if base.endswith(".shifu") else base
    out_path = os.path.join(out_dir, base + ".decrypted")

    try:
        decrypt_file(args.file, password, out_path)
    except Exception as e:
        if os.path.exists(out_path):
            os.remove(out_path)
        # показываем реальную причину вместо общей фразы
        print(f"{Fore.RED}Ошибка расшифровки: {e!r}{Style.RESET_ALL}")
        return 1

    print(f"{Fore.GREEN}Расшифровано: {out_path}{Style.RESET_ALL}")
    return 0


def main():
    print_logo()

    parser = argparse.ArgumentParser(prog="shifu", description="Shifu — шифровальщик любых файлов")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_enc = sub.add_parser("encrypt", help="зашифровать файл")
    p_enc.add_argument("file", help="путь к файлу")
    p_enc.add_argument("-o", "--out", default=None, help="папка вывода (по умолчанию — рядом с файлом)")
    p_enc.set_defaults(func=cmd_encrypt)

    p_dec = sub.add_parser("decrypt", help="расшифровать файл .shifu")
    p_dec.add_argument("file", help="путь к файлу .shifu")
    p_dec.add_argument("-p", "--passfile", default=None, help="явный путь к файлу пароля")
    p_dec.add_argument("-o", "--out", default=None, help="папка вывода (по умолчанию — рядом с файлом)")
    p_dec.set_defaults(func=cmd_decrypt)

    if len(sys.argv) < 2:
        parser.print_help()
        sys.exit(0)

    args = parser.parse_args()
    sys.exit(args.func(args))


if __name__ == "__main__":
    main()

# Shifu (v5)

A CLI file encryption and data protection utility written in Python, featuring hybrid post-quantum cryptography, secret sharing, and steganography.

## Features

- **Key Derivation:** Argon2id with configurable memory, time, and parallelism parameters.
- **Cascaded Authenticated Encryption:** Dual-layer encryption combining `AES-256-GCM` and `ChaCha20-Poly1305` with chunk-offset AAD binding to prevent block reordering.
- **Hybrid Post-Quantum Key Exchange:** Combines `ML-KEM-1024` (Kyber) and `X25519` for quantum-resistant asymmetric encryption.
- **Secret Sharing:** Shamir's Secret Sharing implemented over \(GF(2^8)\) to split master keys into threshold shares.
- **Steganography & Plausible Deniability:** LSB steganography for PNG and WAV carriers with support for decoy containers.
- **Backward Compatibility:** Supports legacy container formats (`SHIFU1`–`SHIFU5`).

## Usage

```bash
python shifu.py --help
```


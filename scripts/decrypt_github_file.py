#!/usr/bin/env python3
"""
Decryption of files encrypted by encrypt_for_github.py
Supports RSA-OAEP, RSA-hybrid and Ed25519 sealed box
"""
import sys
import os
import base64
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_ssh_private_key
from cryptography.hazmat.primitives.asymmetric import rsa, padding as rsa_padding
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

import nacl.signing

def pkcs7_unpad(data):
    """Drop PKCS7 padding"""
    if len(data) == 0:
        raise ValueError("Cannot unpad empty data")
    padding_length = data[-1]
    if padding_length > 16 or padding_length > len(data):
        raise ValueError("Invalid padding")
    if not all(b == padding_length for b in data[-padding_length:]):
        raise ValueError("Invalid padding")
    return data[:-padding_length]

def ed25519_to_x25519_private(ed25519_private_bytes):
    """Convert Ed25519 private key to X25519"""
    signing_key = nacl.signing.SigningKey(ed25519_private_bytes)
    box_key = signing_key.to_curve25519_private_key()
    return bytes(box_key)

def load_private_key(key_path, password=None):
    """Load private key (SSH or PEM format)"""
    with open(key_path, "rb") as f:
        key_data = f.read()
    
    # Try different formats
    errors = []
    
    # 1. SSH format
    try:
        return load_ssh_private_key(key_data, password)
    except Exception as e:
        errors.append(f"SSH format: {e}")
    
    # 2. PEM format
    try:
        return load_pem_private_key(key_data, password, backend=default_backend())
    except Exception as e:
        errors.append(f"PEM: {e}")
    
    raise ValueError(f"Unable to load private key. Tried formats: {'; '.join(errors)}")

def decrypt_rsa_oaep(encrypted_data, private_key):
    """Decrypt RSA-OAEP"""
    plaintext = private_key.decrypt(
        encrypted_data,
        rsa_padding.OAEP(
            mgf=rsa_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return plaintext

def decrypt_rsa_hybrid(encrypted_data, private_key):
    """Decrypt RSA hybrid (RSA + AES-CBC + HMAC)"""
    key_size = private_key.key_size // 8
    
    if len(encrypted_data) < key_size + 48:  # RSA block + IV + HMAC
        raise ValueError("File too small for RSA hybrid format")
    
    # Split components
    encrypted_keys = encrypted_data[:key_size]
    iv = encrypted_data[key_size:key_size + 16]
    hmac_tag_received = encrypted_data[key_size + 16:key_size + 48]
    ciphertext = encrypted_data[key_size + 48:]
    
    if len(ciphertext) % 16 != 0:
        raise ValueError("Ciphertext length is not a multiple of 16")
    
    # Decrypt RSA keys
    key_material = private_key.decrypt(
        encrypted_keys,
        rsa_padding.OAEP(
            mgf=rsa_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    
    if len(key_material) != 64:
        raise ValueError("Invalid key material length")
    
    aes_key = key_material[:32]
    hmac_key = key_material[32:64]
    
    # Verify HMAC
    h = hmac.HMAC(hmac_key, hashes.SHA256())
    h.update(iv)
    h.update(ciphertext)
    
    try:
        h.verify(hmac_tag_received)
    except Exception:
        raise ValueError("HMAC verification failed")
    
    # Decrypt AES-CBC
    cipher = Cipher(
        algorithms.AES(aes_key),
        modes.CBC(iv),
        backend=default_backend()
    )
    decryptor = cipher.decryptor()
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    
    # Remove padding
    plaintext = pkcs7_unpad(padded_plaintext)
    
    return plaintext

def decrypt_ed25519_sealed_box(encrypted_data, ed25519_private_key):
    """Decrypt Ed25519 sealed box"""
    if len(encrypted_data) < 80:
        raise ValueError("File too small for sealed box format")
    
    # Розділення компонентів
    ephemeral_pub_bytes = encrypted_data[0:32]
    iv = encrypted_data[32:48]
    hmac_tag_received = encrypted_data[48:80]
    ciphertext = encrypted_data[80:]
    
    if len(ciphertext) % 16 != 0:
        raise ValueError("Ciphertext length is not a multiple of 16")
    
    # Конвертація Ed25519 → X25519
    ed25519_raw = ed25519_private_key.private_bytes(
        Encoding.Raw, PrivateFormat.Raw, NoEncryption()
    )
    x25519_raw = ed25519_to_x25519_private(ed25519_raw)
    receiver_private_key = x25519.X25519PrivateKey.from_private_bytes(x25519_raw)
    
    # Get ephemeral public key
    ephemeral_public_key = x25519.X25519PublicKey.from_public_bytes(ephemeral_pub_bytes)
    
    # Key exchange
    shared_key = receiver_private_key.exchange(ephemeral_public_key)
    
    # HKDF
    key_material = HKDF(
        algorithm=hashes.SHA256(),
        length=64,
        salt=None,
        info=b'sealed-box-cbc-protocol',
    ).derive(shared_key)
    
    aes_key = key_material[:32]
    hmac_key = key_material[32:64]
    
    # Verify HMAC
    h = hmac.HMAC(hmac_key, hashes.SHA256())
    h.update(ephemeral_pub_bytes)
    h.update(iv)
    h.update(ciphertext)
    
    try:
        h.verify(hmac_tag_received)
    except Exception:
        raise ValueError("HMAC verification failed")
    
    # Decrypt AES-CBC
    cipher = Cipher(
        algorithms.AES(aes_key),
        modes.CBC(iv),
        backend=default_backend()
    )
    decryptor = cipher.decryptor()
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    
    # Remove padding
    plaintext = pkcs7_unpad(padded_plaintext)
    
    return plaintext

def decrypt_file(private_key_path, encrypted_file, output_file, password=None):
    """Automatic format detection and decryption"""
    
    # Load private key
    print(f"Loading private key: {private_key_path}")
    private_key = load_private_key(private_key_path, password)
    
    # Read encrypted file
    print(f"Reading encrypted file: {encrypted_file}")
    with open(encrypted_file, "r") as f:
        encoded_data = f.read().strip()
    
    # Try to decode as base64, if fails assume binary
    try:
        encrypted_data = base64.b64decode(encoded_data)
        print(f"Decoded from base64: {len(encoded_data)} chars → {len(encrypted_data)} bytes")
    except Exception:
        # Not base64, try reading as binary
        with open(encrypted_file, "rb") as f:
            encrypted_data = f.read()
        print(f"Binary format: {len(encrypted_data)} bytes")
    
    # Determine key type
    is_rsa = isinstance(private_key, rsa.RSAPrivateKey)
    is_ed25519 = hasattr(private_key, 'private_bytes') and not is_rsa
    
    plaintext = None
    decryption_method = None
    
    # Attempt decryption
    if is_rsa:
        print("Detected RSA private key")
        
        # Try RSA-OAEP
        try:
            print("Trying RSA-OAEP...")
            plaintext = decrypt_rsa_oaep(encrypted_data, private_key)
            decryption_method = "RSA-OAEP"
        except Exception as e1:
            print(f"  RSA-OAEP failed: {e1}")
            
            # Try RSA hybrid
            try:
                print("Trying RSA hybrid...")
                plaintext = decrypt_rsa_hybrid(encrypted_data, private_key)
                decryption_method = "RSA-hybrid"
            except Exception as e2:
                print(f"  RSA-hybrid failed: {e2}")
                raise ValueError("Unable to decrypt with RSA key")
    
    elif is_ed25519:
        print("Detected Ed25519 private key")
        try:
            print("Trying Ed25519 sealed box...")
            plaintext = decrypt_ed25519_sealed_box(encrypted_data, private_key)
            decryption_method = "Ed25519-sealed-box"
        except Exception as e:
            print(f"  Sealed box failed: {e}")
            raise ValueError("Unable to decrypt with Ed25519 key")
    
    else:
        raise ValueError("Unsupported private key type")
    
    # Write decrypted file
    if plaintext:
        with open(output_file, "wb") as f:
            f.write(plaintext)
        
        print(f"\n✓ Successfully decrypted using {decryption_method}")
        print(f"  Output: {output_file}")
        print(f"  Size: {len(plaintext)} bytes")
        return True
    
    return False

def main():
    if len(sys.argv) < 4:
        print("Usage: python3 decrypt_github_file.py <private_key> <encrypted_file> <output_file> [password]")
        print()
        print("Examples:")
        print("  # RSA key")
        print("  python3 decrypt_github_file.py ~/.ssh/id_rsa file.rsa.enc decrypted.txt")
        print()
        print("  # Ed25519 key with password")
        print("  python3 decrypt_github_file.py ~/.ssh/id_ed25519 file.ed25519.enc decrypted.txt mypassword")
        print()
        print("Supported formats:")
        print("  - RSA-OAEP (small files)")
        print("  - RSA-hybrid (RSA + AES-CBC + HMAC)")
        print("  - Ed25519 sealed box (X25519 + AES-CBC + HMAC)")
        sys.exit(1)
    
    private_key_path = sys.argv[1]
    encrypted_file = sys.argv[2]
    output_file = sys.argv[3]
    password = sys.argv[4].encode() if len(sys.argv) > 4 else None
    
    try:
        decrypt_file(private_key_path, encrypted_file, output_file, password)
    except Exception as e:
        print(f"\n❌ Decryption failed: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()

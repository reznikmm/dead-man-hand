#!/usr/bin/env python3
"""
Encrypts a file with all public SSH keys of a GitHub user.
Supports RSA and Ed25519 keys.
"""
import sys
import os
import base64
import requests
from cryptography.hazmat.primitives.serialization import load_ssh_public_key
from cryptography.hazmat.primitives.asymmetric import rsa, padding as rsa_padding
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.serialization import PublicFormat, Encoding
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

import nacl.signing

def fetch_github_keys(username):
    """Fetches public SSH keys from GitHub"""
    url = f"https://github.com/{username}.keys"
    print(f"Fetching keys from: {url}")
    
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        
        keys_text = response.text.strip()
        if not keys_text:
            print(f"No public keys found for user: {username}")
            return []
        
        keys = [line.strip() for line in keys_text.split('\n') if line.strip()]
        print(f"Found {len(keys)} key(s)")
        return keys
        
    except requests.RequestException as e:
        print(f"Error fetching keys: {e}")
        sys.exit(1)

def ed25519_to_x25519(ed25519_pubkey_bytes):
    """Converts Ed25519 public key to X25519"""
    verify_key = nacl.signing.VerifyKey(ed25519_pubkey_bytes)
    box_pubkey = verify_key.to_curve25519_public_key()
    return bytes(box_pubkey)

def pkcs7_pad(data, block_size=16):
    """Adds PKCS7 padding"""
    padding_length = block_size - (len(data) % block_size)
    padding = bytes([padding_length] * padding_length)
    return data + padding

def encrypt_with_rsa(plaintext, rsa_public_key, output_path):
    """
    Encrypts a file with RSA-OAEP.
    
    Format: [ciphertext]
    RSA can only encrypt a limited amount of data, so we encrypt only small files
    or use hybrid encryption (RSA for key, AES for data).
    """
    # Check size
    key_size = rsa_public_key.key_size // 8  # in bytes
    max_plaintext = key_size - 2 * 32 - 2  # OAEP padding overhead
    
    if len(plaintext) > max_plaintext:
        print(f"  ⚠️  File too large for direct RSA encryption ({len(plaintext)} > {max_plaintext} bytes)")
        print(f"  Using hybrid encryption (RSA + AES-256-CBC)")
        return encrypt_with_rsa_hybrid(plaintext, rsa_public_key, output_path)
    
    # Direct RSA encryption
    ciphertext = rsa_public_key.encrypt(
        plaintext,
        rsa_padding.OAEP(
            mgf=rsa_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    
    # Encode to base64
    encoded = base64.b64encode(ciphertext).decode('ascii')
    
    with open(output_path, "w") as f:
        f.write(encoded)
    
    print(f"  ✓ RSA-OAEP encrypted: {output_path}")
    print(f"    Plaintext: {len(plaintext)} bytes → Ciphertext: {len(ciphertext)} bytes → Base64: {len(encoded)} chars")

def encrypt_with_rsa_hybrid(plaintext, rsa_public_key, output_path):
    """
    Hybrid encryption: RSA for symmetric key, AES-CBC for data.
    
    Format:
    [256 bytes: RSA encrypted key material]
    [16 bytes: IV]
    [32 bytes: HMAC]
    [N bytes: AES-CBC ciphertext]
    """
    # Generate random keys
    aes_key = os.urandom(32)  # AES-256
    hmac_key = os.urandom(32)  # HMAC-SHA256
    iv = os.urandom(16)
    
    # Encrypt keys with RSA
    key_material = aes_key + hmac_key  # 64 bytes
    encrypted_keys = rsa_public_key.encrypt(
        key_material,
        rsa_padding.OAEP(
            mgf=rsa_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    
    # Encrypt data with AES-CBC
    padded_plaintext = pkcs7_pad(plaintext)
    cipher = Cipher(
        algorithms.AES(aes_key),
        modes.CBC(iv),
        backend=default_backend()
    )
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()
    
    # Calculate HMAC
    h = hmac.HMAC(hmac_key, hashes.SHA256())
    h.update(iv)
    h.update(ciphertext)
    hmac_tag = h.finalize()
    
    # Write: encrypted_keys | IV | HMAC | ciphertext
    binary_data = encrypted_keys + iv + hmac_tag + ciphertext
    
    # Encode to base64
    encoded = base64.b64encode(binary_data).decode('ascii')
    
    with open(output_path, "w") as f:
        f.write(encoded)
    
    print(f"  ✓ RSA-hybrid encrypted: {output_path}")
    print(f"    Plaintext: {len(plaintext)} bytes → Binary: {len(binary_data)} bytes → Base64: {len(encoded)} chars")

def encrypt_with_ed25519(plaintext, ed25519_public_key, output_path):
    """
    Encrypts a file using Ed25519→X25519 + AES-CBC + HMAC (sealed box).
    
    Format:
    [32 bytes: ephemeral X25519 public key]
    [16 bytes: IV]
    [32 bytes: HMAC]
    [N bytes: AES-CBC ciphertext]
    """
    # Convert Ed25519 → X25519
    ed25519_raw = ed25519_public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)
    x25519_raw = ed25519_to_x25519(ed25519_raw)
    receiver_pubkey = x25519.X25519PublicKey.from_public_bytes(x25519_raw)
    
    # Generate ephemeral key
    ephemeral_private_key = x25519.X25519PrivateKey.generate()
    ephemeral_public_key = ephemeral_private_key.public_key()
    
    # Key exchange
    shared_key = ephemeral_private_key.exchange(receiver_pubkey)
    
    # HKDF derivation
    key_material = HKDF(
        algorithm=hashes.SHA256(),
        length=64,
        salt=None,
        info=b'sealed-box-cbc-protocol',
    ).derive(shared_key)
    
    aes_key = key_material[:32]
    hmac_key = key_material[32:64]
    
    # Generate IV
    iv = os.urandom(16)
    
    # AES-CBC encryption
    padded_plaintext = pkcs7_pad(plaintext)
    cipher = Cipher(
        algorithms.AES(aes_key),
        modes.CBC(iv),
        backend=default_backend()
    )
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()
    
    # HMAC
    h = hmac.HMAC(hmac_key, hashes.SHA256())
    ephemeral_pub_bytes = ephemeral_public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)
    h.update(ephemeral_pub_bytes)
    h.update(iv)
    h.update(ciphertext)
    hmac_tag = h.finalize()
    
    # Write: ephemeral_pub | IV | HMAC | ciphertext
    binary_data = ephemeral_pub_bytes + iv + hmac_tag + ciphertext
    
    # Encode to base64
    encoded = base64.b64encode(binary_data).decode('ascii')
    
    with open(output_path, "w") as f:
        f.write(encoded)
    
    print(f"  ✓ Ed25519 sealed box encrypted: {output_path}")
    print(f"    Plaintext: {len(plaintext)} bytes → Binary: {len(binary_data)} bytes → Base64: {len(encoded)} chars")

def encrypt_file_for_github_user(username, input_file):
    """Main function: encrypts file with all user keys"""
    
    # Check input file
    if not os.path.exists(input_file):
        print(f"Error: File not found: {input_file}")
        sys.exit(1)
    
    # Read plaintext
    with open(input_file, "rb") as f:
        plaintext = f.read()
    
    print(f"\nInput file: {input_file}")
    print(f"Size: {len(plaintext)} bytes\n")
    
    # Load keys
    keys = fetch_github_keys(username)
    
    if not keys:
        print("No keys to process")
        sys.exit(1)
    
    print()
    
    # Process each key
    encrypted_count = 0
    base_filename = os.path.splitext(os.path.basename(input_file))[0]
    
    for idx, key_line in enumerate(keys, 1):
        print(f"Processing key {idx}/{len(keys)}...")
        
        try:
            # Parse SSH key
            public_key = load_ssh_public_key(key_line.encode())
            
            # Determine key type
            if key_line.startswith("ssh-rsa"):
                key_type = "rsa"
                output_file = f"{base_filename}.{username}.{idx}.rsa.enc"
                
                if isinstance(public_key, rsa.RSAPublicKey):
                    encrypt_with_rsa(plaintext, public_key, output_file)
                    encrypted_count += 1
                else:
                    print(f"  ⚠️  Key type mismatch (expected RSA)")
                    
            elif key_line.startswith("ssh-ed25519"):
                key_type = "ed25519"
                output_file = f"{base_filename}.{username}.{idx}.ed25519.enc"
                
                encrypt_with_ed25519(plaintext, public_key, output_file)
                encrypted_count += 1
                
            else:
                key_type = "unknown"
                print(f"  ⚠️  Unsupported key type: {key_line.split()[0]}")
                
        except Exception as e:
            print(f"  ❌ Error processing key: {e}")
            continue
        
        print()
    
    print("=" * 60)
    print(f"✓ Successfully encrypted with {encrypted_count}/{len(keys)} key(s)")
    print("=" * 60)

def main():
    if len(sys.argv) != 3:
        print("Usage: python3 encrypt_for_github.py <github_username> <file_to_encrypt>")
        print()
        print("Example:")
        print("  python3 encrypt_for_github.py reznikmm secret.txt")
        print()
        print("This will:")
        print("  1. Fetch all public SSH keys from https://github.com/<username>.keys")
        print("  2. Encrypt the file with each key:")
        print("     - RSA keys: RSA-OAEP or hybrid RSA+AES-CBC")
        print("     - Ed25519 keys: X25519 sealed box with AES-CBC+HMAC")
        print("  3. Save encrypted files as: <filename>.<username>.<n>.<keytype>.enc")
        sys.exit(1)
    
    username = sys.argv[1]
    input_file = sys.argv[2]
    
    encrypt_file_for_github_user(username, input_file)

if __name__ == "__main__":
    main()

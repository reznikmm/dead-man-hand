# dead-man-hand

This program helps decrypt files with links to Ada 2022 videos.

Simply build it with Alire and run:

```shell
alr build
./bin/dead_man_hand <your-github-name>
```

## How it works

Files encrypted with each user/keys are stored in the `data/` directory.

The program downloads the corresponding file from GitHub and decrypts it by running openssl.
Both RSA and Ed25519 keys are supported.

### RSA case
* Base64 is decoded
* If the key is not in PEM format, a copy is made and converted to PEM format that `openssl` can work with
* `openssl` is executed and the decryption result is saved to `result-rsa.txt`

### Ed25519 case
* Base64 is decoded
* If the private key has a password, a temporary copy is made, the password is removed, the key is read, and the copy is deleted
* The key is converted from ed25519 to x25519 format, and encryption and verification keys are restored using `openssl`
* The file is decrypted and the result is saved to `result-ed.txt`

## Optional flags

```
Usage: dead_man_hand [options] <github-username>
Options:
  --rsa-key <path>     Path to RSA private key (default: ~/.ssh/id_rsa)
  --ed25519-key <path> Path to ED25519 private key (default: ~/.ssh/id_ed25519)
  --rsa-file <path>    Path to local RSA encrypted file
  --ed-file <path>     Path to local ED25519 encrypted file
  --verbose            Enable verbose logging
```

Options `--rsa-file` and `--ed-file` are used to avoid downloading encrypted from GitHub for debugging.

## Python alternative

There's an option to use a Python script instead of the Ada program and openssl:

```shell
pip install cryptography requests pynacl
python ./scripts/decrypt_github_file.py <private_key> <encrypted_file> <output_file> [password]
```

## Good luck!

# ECDH key exchange with AES-GCM

## Setup

```
python -m venv ./venv
source venv/bin/activate
python -m pip install -r requirements.txt
```

## Usage

`node gen-keypair.js` to generate ECDH keypairs.

`node flame-crypto.js` and `python flame-crypto.py` should generate the same output (except for the encrypted blobs).

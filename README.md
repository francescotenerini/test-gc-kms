# Google Cloud safe memory PoC

This application provides tools to generate an RSA key pair and sign and
verify a text file.

## Prerequisites

- [uv](https://docs.astral.sh/uv/)
- [Google Cloud KMS PKCS#11 drivers](https://github.com/GoogleCloudPlatform/kms-integrations/releases)
- A Google Cloud account with an existing project.
- A local environment ready to authenticate your Google Cloud user.
- Openssl

## How to use

Sync the environment using uv:

    uv sync

This should install both python and the dependencies.

Configure the environment variables:

- `PROJECT_ID`: the project id in google cloud
- `LOCATION_ID`: the desired keyring location (eg. `global`)
- `KEY_RING_ID`: the keyring name
- `KEY_ID`: the secure key name
- `PKCS11_MODULE_PATH`: the absolute path to the pkcs11 module
  downloaded from google.
- `KMS_PKCS11_CONFIG`: the absolute path to `pkcs11-config.yaml`

Now fix the `pkcs11-config.yaml` with the correct project id and key
ring id.
This is needed to use the keys with openssl.

**NOTE**: `openssl` is needed to create a CSR, the python library needs
the private key for that and getting it from KMS is not allowed because
it will break the safety of the key. The PKCS#11 interface provides the
tools to use the private key without it to leave the "safe world".

Make sure your environment is ready to connect to google cloud using
the SDK (follow
the [cli install documentation](https://cloud.google.com/sdk/docs/install-sdk).
Now you can use the python program in `src/main.py`.

### Create the keyring and the key

    python src/main.py create-key-ring

This will create both the keyring and the HSM key in your project.

### Sign a text file

    python src/main.py sign-asymmetric

This will sign `bar.txt`, printing in standard output the signature.

### Verify a file

    python src/main.py verify-asymmetric-rsa

This verifies that the sing in `bar.txt.sign` is the correct signature of
the file `bar.txt`.

### Create a CSR

As already stated, we need `openssl` to generate a CRS.
Check the script `csr_create.sh` to fix the environment variables
initialization, then run.

    bash csr_create.sh

This should create the file `my-request.csr` with the Common Name set
as `test`.
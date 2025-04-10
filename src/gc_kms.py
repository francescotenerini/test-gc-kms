# import datetime
#
# from google.protobuf import duration_pb2  # type: ignore
# Import base64 for printing the ciphertext.
import base64

# Import hashlib for calculating hashes.
import hashlib

from google.cloud import kms
from google.cloud.kms_v1 import KeyRing

# Import cryptographic helpers from the cryptography package.
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import utils


def create_key_ring(
        project_id: str, location_id: str, key_ring_id: str
) -> KeyRing:
    """
    Creates a new key ring in Cloud KMS

    Args:
        project_id (string): Google Cloud project ID (e.g. 'my-project').
        location_id (string): Cloud KMS location (e.g. 'us-east1').
        key_ring_id (string): ID of the key ring to create (e.g. 'my-key-ring').

    Returns:
        KeyRing: Cloud KMS key ring.

    """

    # Create the client.
    client = kms.KeyManagementServiceClient()

    # Build the parent location name.
    location_name = f"projects/{project_id}/locations/{location_id}"

    # Build the key ring.
    key_ring = {}

    # Call the API.
    created_key_ring = client.create_key_ring(
        request={
            "parent": location_name,
            "key_ring_id": key_ring_id,
            "key_ring": key_ring,
        }
    )
    print(f"Created key ring: {created_key_ring.name}")
    return created_key_ring


def create_key_hsm(
        project_id: str, location_id: str, key_ring_id: str, key_id: str
) -> kms.CryptoKey:
    """
    Creates a new key in Cloud KMS backed by Cloud HSM.

    Args:
        project_id (string): Google Cloud project ID (e.g. 'my-project').
        location_id (string): Cloud KMS location (e.g. 'us-east1').
        key_ring_id (string): ID of the Cloud KMS key ring (e.g. 'my-key-ring').
        key_id (string): ID of the key to create (e.g. 'my-hsm-key').

    Returns:
        CryptoKey: Cloud KMS key.

    """

    # Create the client.
    client = kms.KeyManagementServiceClient()

    # Build the parent key ring name.
    key_ring_name = client.key_ring_path(project_id, location_id, key_ring_id)

    # Build the key.
    # purpose = kms.CryptoKey.CryptoKeyPurpose.ENCRYPT_DECRYPT
    purpose = kms.CryptoKey.CryptoKeyPurpose.ASYMMETRIC_SIGN
    algorithm = (
        # kms.CryptoKeyVersion.CryptoKeyVersionAlgorithm.GOOGLE_SYMMETRIC_ENCRYPTION
        kms.CryptoKeyVersion.CryptoKeyVersionAlgorithm.RSA_SIGN_PKCS1_4096_SHA512
    )
    protection_level = kms.ProtectionLevel.HSM
    key = {
        "purpose": purpose,
        "version_template": {
            "algorithm": algorithm,
            "protection_level": protection_level,
        },
        # Optional: customize how long key versions should be kept before
        # destroying.
        # "destroy_scheduled_duration": duration_pb2.Duration().FromTimedelta(
        #     datetime.timedelta(days=1)
        # ),
    }

    # Call the API.
    created_key = client.create_crypto_key(
        request={"parent": key_ring_name, "crypto_key_id": key_id, "crypto_key": key}
    )
    print(f"Created hsm key: {created_key.name}")
    return created_key


def sign_asymmetric(
        project_id: str,
        location_id: str,
        key_ring_id: str,
        key_id: str,
        version_id: str,
        message: str,
) -> kms.AsymmetricSignResponse:
    """
    Sign a message using the private key part of an asymmetric key.

    Args:
        project_id (string): Google Cloud project ID (e.g. 'my-project').
        location_id (string): Cloud KMS location (e.g. 'us-east1').
        key_ring_id (string): ID of the Cloud KMS key ring (e.g. 'my-key-ring').
        key_id (string): ID of the key to use (e.g. 'my-key').
        version_id (string): Version to use (e.g. '1').
        message (string): Message to sign.

    Returns:
        AsymmetricSignResponse: Signature.
    """

    # Create the client.
    client = kms.KeyManagementServiceClient()

    # Build the key version name.
    key_version_name = client.crypto_key_version_path(
        project_id, location_id, key_ring_id, key_id, version_id
    )

    # Convert the message to bytes.
    message_bytes = message.encode("utf-8")

    # Calculate the hash. NOTE: using sha512 because of CryptoKeyVersionAlgorithm
    hash_ = hashlib.sha512(message_bytes).digest()

    # Build the digest.
    #
    # Note: Key algorithms will require a varying hash function. For
    # example, EC_SIGN_P384_SHA384 requires SHA-384.
    digest = {"sha512": hash_}

    # Optional, but recommended: compute digest's CRC32C.
    # See crc32c() function defined below.
    digest_crc32c = crc32c(hash_)

    # Call the API
    sign_response = client.asymmetric_sign(
        request={
            "name": key_version_name,
            "digest": digest,
            "digest_crc32c": digest_crc32c,
        }
    )

    # Optional, but recommended: perform integrity verification on sign_response.
    # For more details on ensuring E2E in-transit integrity to and from Cloud KMS visit:
    # https://cloud.google.com/kms/docs/data-integrity-guidelines
    if not sign_response.verified_digest_crc32c:
        raise Exception("The request sent to the server was corrupted in-transit.")
    if not sign_response.name == key_version_name:
        raise Exception("The request sent to the server was corrupted in-transit.")
    if not sign_response.signature_crc32c == crc32c(sign_response.signature):
        raise Exception(
            "The response received from the server was corrupted in-transit."
        )
    # End integrity verification

    print(f"Signature: {base64.b64encode(sign_response.signature)!r}")
    return sign_response


def crc32c(data: bytes) -> int:
    """
    Calculates the CRC32C checksum of the provided data.
    Args:
        data: the bytes over which the checksum should be calculated.
    Returns:
        An int representing the CRC32C checksum of the provided bytes.
    """
    import crcmod  # type: ignore

    crc32c_fun = crcmod.predefined.mkPredefinedCrcFun("crc-32c")
    return crc32c_fun(data)


def verify_asymmetric_rsa(
        project_id: str,
        location_id: str,
        key_ring_id: str,
        key_id: str,
        version_id: str,
        message: str,
        signature: bytes,
) -> bool:
    """
    Verify the signature of an message signed with an asymmetric RSA key.

    Args:
        project_id (string): Google Cloud project ID (e.g. 'my-project').
        location_id (string): Cloud KMS location (e.g. 'us-east1').
        key_ring_id (string): ID of the Cloud KMS key ring (e.g. 'my-key-ring').
        key_id (string): ID of the key to use (e.g. 'my-key').
        version_id (string): ID of the version to use (e.g. '1').
        message (string): Original message (e.g. 'my message')
        signature (bytes): Signature from a sign request.

    Returns:
        bool: True if verified, False otherwise

    """

    # Convert the message to bytes.
    message_bytes = message.encode("utf-8")

    # Create the client.
    client = kms.KeyManagementServiceClient()

    # Build the key version name.
    key_version_name = client.crypto_key_version_path(
        project_id, location_id, key_ring_id, key_id, version_id
    )

    # Get the public key.
    public_key = client.get_public_key(request={"name": key_version_name})

    # Extract and parse the public key as a PEM-encoded RSA key.
    pem = public_key.pem.encode("utf-8")
    rsa_key = serialization.load_pem_public_key(pem, default_backend())
    hash_ = hashlib.sha512(message_bytes).digest()

    # Attempt to verify.
    try:
        sha512 = hashes.SHA512()
        pad = padding.PKCS1v15()
        rsa_key.verify(signature, hash_, pad, utils.Prehashed(sha512))
        print("Signature verified")
        return True
    except InvalidSignature:
        print("Signature failed to verify")
        return False

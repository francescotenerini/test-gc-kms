import os

from gc_kms import create_key_ring, create_key_hsm, sign_asymmetric, verify_asymmetric_rsa

PROJECT_ID = os.environ["PROJECT_ID"]
LOCATION_ID = os.environ["LOCATION_ID"]
KEY_RING_ID = os.environ["KEY_RING_ID"]
KEY_ID = os.environ["KEY_ID"]


def main():
    # create_key_ring(PROJECT_ID, LOCATION_ID, KEY_RING_ID)
    # create_key_hsm(
    #     project_id=PROJECT_ID,
    #     location_id=LOCATION_ID,
    #     key_ring_id=KEY_RING_ID,
    #     key_id=KEY_ID,
    # )

    with open("bar.txt", "r") as f:
        text = f.read()
    # sign_asymmetric(
    #     project_id=PROJECT_ID,
    #     location_id=LOCATION_ID,
    #     key_ring_id=KEY_RING_ID,
    #     key_id=KEY_ID,
    #     version_id="1",
    #     message=text
    # )

    with open("bar.txt.sign", "rb") as f:
        sign = f.read()
    verify_asymmetric_rsa(
        project_id=PROJECT_ID,
        location_id=LOCATION_ID,
        key_ring_id=KEY_RING_ID,
        key_id=KEY_ID,
        version_id="1",
        signature=sign,
        message=text,
    )


if __name__ == "__main__":
    main()

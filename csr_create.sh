#!/bin/bash

# https://github.com/GoogleCloudPlatform/kms-integrations/releases
# FIXME: use absolute path
export PKCS11_MODULE_PATH="./libkmsp11-1.6-linux-amd64/libkmsp11.so"
export KMS_PKCS11_CONFIG="./pkcs11-config.yaml"


# FIXME: add project id
export PROJECT_ID=""
export LOCATION_ID="global"
export KEY_RING_ID="test-hsm"
export KEY_ID="tmp-hsm"

chmod 644 pkcs11-config.yaml
openssl req -new -subj '/CN=test/' -sha512 -engine pkcs11 -keyform engine -key pkcs11:object=${KEY_ID} > my-request.csr

#!/bin/bash

# https://github.com/GoogleCloudPlatform/kms-integrations/releases
export PKCS11_MODULE_PATH="/home/francesco/src/test_py/kms/libkmsp11-1.6-linux-amd64/libkmsp11.so"
export KMS_PKCS11_CONFIG="/home/francesco/src/test_py/kms/pkcs11-config.yaml"


export PROJECT_ID="siqtraq-208312"
export LOCATION_ID="global"
export KEY_RING_ID="test-hsm"
export KEY_ID="tmp-hsm"

chmod 644 pkcs11-config.yaml
openssl req -new -subj '/CN=test/' -sha512 -engine pkcs11 -keyform engine -key pkcs11:object=${KEY_ID} > my-request.csr

openssl dgst -sha512 -engine pkcs11 -keyform engine -sign pkcs11:object="${KEY_ID}" -out "$1".sign "$1"
openssl base64 -in "$1".sign -out "$1".sign.b64

# openssl base64 -d -in $signature -out /tmp/$filename.sha256
# openssl base64 -d -in "$1".sign.b64 -out "$1".sign

openssl dgst -sha512 -verify !! certificato pubblico !! -signature /tmp/"$1".sign $1
# openssl dgst -sha512 -engine pkcs11 -keyform engine -sign pkcs11:object="${KEY_ID}" -out "$1".sign "$1"

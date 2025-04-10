def generate_csr(pkcs11_module : str, token_label : str):
    # L'unica e' chiamare openssl, se non si vuole reimplementare la creazione del csr
    # a mano. cryptography vuole la chiave privata nell'API, la funziona e' implementata
    # in rust. La chiave privata serve per estrarre la chiave pubblica e firmare il csr.
    # il modulo pkcs di google kms is trova qua:
    # https://github.com/GoogleCloudPlatform/kms-integrations/releases
    pass

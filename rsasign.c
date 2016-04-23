#include "crypto_sign/sphincs256/ref/api.h"

int rsasignjs_public_key_bytes () {
	return CRYPTO_PUBLICKEYBYTES;
}

int rsasignjs_secret_key_bytes () {
	return CRYPTO_SECRETKEYBYTES;
}

int rsasignjs_signature_bytes () {
	return CRYPTO_BYTES;
}

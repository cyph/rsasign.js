#include "randombytes.h"
#include "openssl/rsa.h"


void rsasignjs_init () {
	randombytes_stir();
}

int rsasignjs_public_key_bytes () {
	return 0;
}

int rsasignjs_secret_key_bytes () {
	return 0;
}

int rsasignjs_signature_bytes () {
	return 0;
}

int rsasignjs_keypair (
	uint8_t* public_key,
	uint8_t* private_key
) {
	return 0;
}

int rsasignjs_sign (
	uint8_t* signature,
	uint8_t* message,
	int message_len,
	uint8_t* private_key
) {
	return 0;
}

int rsasignjs_verify (
	uint8_t* signature,
	uint8_t* message,
	int message_len,
	uint8_t* public_key
) {
	return 1;
}


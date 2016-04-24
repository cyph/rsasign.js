#include "rsasign.h"

size_t public_key_len;
size_t private_key_len;


int rsasignjs_public_key_bytes () {
	return public_key_len;
}

int rsasignjs_secret_key_bytes () {
	return private_key_len;
}

int rsasignjs_signature_bytes () {
	return RSASIGNJS_SIGLEN;
}

int rsasignjs_keypair (
	uint8_t* public_key,
	uint8_t* private_key
) {
	RSA* rsa	= FIPS_rsa_new();

	if (FIPS_rsa_generate_key_ex(rsa, RSASIGNJS_BITS, NULL, NULL) != 1) {
		return 1;
	}
	
	public_key_len	= i2d_RSAPublicKey(rsa, &public_key);
	private_key_len	= i2d_RSAPrivateKey(rsa, &private_key);

	FIPS_rsa_free(rsa);

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

void rsasignjs_init (const void *seed, int seed_len) {
	FIPS_x931_seed(seed, seed_len);

	uint8_t* public_key;
	uint8_t* private_key;
	rsasignjs_keypair(
		public_key,
		private_key
	);
	free(public_key);
	free(private_key);
}

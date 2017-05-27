#include "openssl/asn1.h"
#include "openssl/asn1t.h"
#include "openssl/rand.h"
#include "openssl/rsa.h"
#include "openssl/x509.h"
#include "randombytes.h"


void rsasignjs_init () {
	randombytes_stir();
}

int rsasignjs_public_key_bytes () {
	return RSASIGNJS_PUBLEN;
}

int rsasignjs_secret_key_bytes () {
	return RSASIGNJS_PRIVLEN;
}

int rsasignjs_signature_bytes () {
	return RSASIGNJS_SIGLEN;
}

int rsasignjs_keypair (
	uint8_t* public_key,
	uint8_t* private_key
) {
	BIGNUM* prime	= BN_new();
	RSA* rsa		= RSA_new();

	BN_add_word(prime, RSA_F4);

	if (RSA_generate_key_ex(rsa, RSASIGNJS_BITS, prime, NULL) != 1) {
		return 1;
	}
	
	i2d_RSA_PUBKEY(rsa, &public_key);
	i2d_RSAPrivateKey(rsa, &private_key);

	RSA_free(rsa);
	BN_free(prime);

	return 0;
}

int rsasignjs_sign (
	uint8_t* signature,
	uint8_t* message,
	int message_len,
	const uint8_t* private_key
) {
	RSA* rsa	= RSA_new();

	d2i_RSAPrivateKey(&rsa, &private_key, RSASIGNJS_PRIVLEN);

	int status	= RSA_sign_ASN1_OCTET_STRING(
		NID_sha256,
		message,
		message_len,
		signature,
		NULL,
		rsa
	);

	RSA_free(rsa);

	return status;
}

int rsasignjs_verify (
	uint8_t* signature,
	uint8_t* message,
	int message_len,
	const uint8_t* public_key
) {
	RSA* rsa	= RSA_new();

	d2i_RSA_PUBKEY(&rsa, &public_key, RSASIGNJS_PUBLEN);

	int status	= RSA_verify_ASN1_OCTET_STRING(
		NID_sha256,
		message,
		message_len,
		signature,
		RSASIGNJS_SIGLEN,
		rsa
	);

	RSA_free(rsa);

	return status;
}


void RAND_add (const void *buf, int num, double entropy) {
	randombytes_stir();
}

int RAND_bytes (unsigned char *buf, int num) {
	randombytes_buf(buf, num);
	return 1;
}

int RAND_pseudo_bytes (unsigned char *buf, int num) {
	return RAND_bytes(buf, num);
}

void RAND_seed (const void *buf, int num) {
	randombytes_stir();
}

int RAND_status () {
	return 1;
}

void rand_cleanup_int () {}

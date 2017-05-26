# rsa-sign.js

## Overview

[RSASSA-PKCS1-v1_5](https://tools.ietf.org/html/rfc3447#section-8.2) with key length 2048 and 
hash function [SHA-256](https://en.wikipedia.org/wiki/SHA-2) wrapped for usage in JavaScript
via [SubtleCrypto](https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto) and
[Emscripten](https://github.com/kripken/emscripten).

## Example Usage

	const keyPair /*: {privateKey: Uint8Array; publicKey: Uint8Array} */ =
		rsaSign.keyPair()
	;

	const message /*: Uint8Array */ =
		new Uint8Array([104, 101, 108, 108, 111, 0]) // "hello"
	;

	/* Combined signatures */

	const signed /*: Uint8Array */ =
		rsaSign.sign(message, keyPair.privateKey)
	;

	const verified /*: Uint8Array */ =
		rsaSign.open(signed, keyPair.publicKey) // same as message
	;

	/* Detached signatures */
	
	const signature /*: Uint8Array */ =
		rsaSign.signDetached(message, keyPair.privateKey)
	;

	const isValid /*: boolean */ =
		rsaSign.verifyDetached(signature, message, keyPair.publicKey) // true
	;

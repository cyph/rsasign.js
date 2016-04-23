# rsa-sign.js

## Overview

[RSASSA-PKCS1-v1_5](https://tools.ietf.org/html/rfc3447#section-8.2) with key length 2048 and 
hash function [SHA-256](https://en.wikipedia.org/wiki/SHA-2) wrapped for usage in JavaScript
via [SubtleCrypto](https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto) and
[Emscripten](https://github.com/kripken/emscripten).

## Example Usage

	var keyPair		= rsaSign.keyPair();
	var message		= new Uint8Array([104, 101, 108, 108, 111, 0]); // "hello"

	var signed		= rsaSign.sign(message, keyPair.privateKey);
	var verified	= rsaSign.open(signed, keyPair.publicKey); // same as message
	
	var signature	= rsaSign.signDetached(message, keyPair.privateKey);
	var isValid		= rsaSign.verifyDetached(signature, message, keyPair.publicKey); // true

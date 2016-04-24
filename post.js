;

function dataReturn (returnValue, result) {
	if (returnValue === 0) {
		return result;
	}
	else {
		throw new Error('RSA error: ' + returnValue);
	}
}

function dataResult (buffer, bytes) {
	return new Uint8Array(
		new Uint8Array(Module.HEAPU8.buffer, buffer, bytes)
	);
}

function dataFree (buffer) {
	try {
		Module._free(buffer);
	}
	catch (_) {}
}

function dereferenceNumber (buffer) {
	return new Uint32Array(Module.HEAPU32.buffer, buffer, 1)[0];
}


var seedLength	= 512;
var seed		= Module._malloc(seedLength);
crypto.getRandomValues(new Uint8Array(Module.HEAPU8.buffer, seed, seedLength));
Module._rsasignjs_init(seed, seedLength);
Module._free(seed);


var rsaSign	= {
	publicKeyLength: Module._rsasignjs_public_key_bytes(),
	privateKeyLength: Module._rsasignjs_secret_key_bytes(),
	signatureLength: Module._rsasignjs_signature_bytes(),

	keyPair: function () {
		var publicKeyBuffer;
		var publicKeyBufferBuffer	= Module._malloc(4);

		var privateKeyBuffer;
		var privateKeyBufferBuffer	= Module._malloc(4);

		try {
			var returnValue	= Module._rsasignjs_keypair(
				publicKeyBufferBuffer,
				privateKeyBufferBuffer
			);

			publicKeyBuffer		= dereferenceNumber(publicKeyBufferBuffer);
			privateKeyBuffer	= dereferenceNumber(privateKeyBufferBuffer);

			return dataReturn(returnValue, {
				publicKey: dataResult(
					publicKeyBuffer,
					rsaSign.publicKeyLength
				),
				privateKey: dataResult(
					privateKeyBuffer,
					rsaSign.privateKeyLength
				)
			});
		}
		finally {
			dataFree(publicKeyBuffer);
			dataFree(publicKeyBufferBuffer);
			dataFree(privateKeyBuffer);
			dataFree(privateKeyBufferBuffer);
		}
	},

	sign: function (message, privateKey) {
		var signature	= rsaSign.signDetached(message, privateKey);
		var signed		= new Uint8Array(rsaSign.signatureLength + message.length);
		signed.set(signature);
		signed.set(message, rsaSign.signatureLength);
		return signed;
	},

	signDetached: function (message, privateKey) {
		var signatureBuffer		= Module._malloc(rsaSign.signatureLength);
		var messageBuffer		= Module._malloc(message.length);
		var privateKeyBuffer	= Module._malloc(rsaSign.privateKeyLength);

		Module.writeArrayToMemory(message, messageBuffer);
		Module.writeArrayToMemory(privateKey, privateKeyBuffer);

		try {
			var returnValue	= Module._rsasignjs_sign(
				signatureBuffer,
				messageBuffer,
				message.length,
				privateKeyBuffer
			);

			return dataReturn(
				returnValue,
				dataResult(signatureBuffer, rsaSign.signatureLength)
			);
		}
		finally {
			dataFree(signatureBuffer);
			dataFree(messageBuffer);
			dataFree(privateKeyBuffer);
		}
	},

	open: function (signed, publicKey) {
		var signature	= new Uint8Array(signed.buffer, 0, rsaSign.signatureLength);
		var message		= new Uint8Array(signed.buffer, rsaSign.signatureLength);

		if (rsaSign.verifyDetached(signature, message, publicKey)) {
			return message;
		}
		else {
			dataResult('Invalid signature.');
		}
	},

	verifyDetached: function (signature, message, publicKey) {
		var signatureBuffer	= Module._malloc(rsaSign.signatureLength);
		var messageBuffer	= Module._malloc(message.length);
		var publicKeyBuffer	= Module._malloc(rsaSign.publicKeyLength);

		Module.writeArrayToMemory(signature, signatureBuffer);
		Module.writeArrayToMemory(message, messageBuffer);
		Module.writeArrayToMemory(publicKey, publicKeyBuffer);

		try {
			return Module._rsasignjs_verify(
				signatureBuffer,
				messageBuffer,
				message.length,
				publicKeyBuffer
			) === 1;
		}
		finally {
			dataFree(signatureBuffer);
			dataFree(messageBuffer);
			dataFree(publicKeyBuffer);
		}
	}
};



return rsaSign;

}());

self.rsaSign	= rsaSign;

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


Module._randombytes_stir();


var rsaSign	= {
	publicKeyLength: Module._rsasignjs_public_key_bytes(),
	privateKeyLength: Module._rsasignjs_secret_key_bytes(),
	signatureLength: Module._rsasignjs_signature_bytes(),

	keyPair: function () {
		var publicKeyBuffer		= Module._malloc(rsaSign.publicKeyLength);
		var privateKeyBuffer	= Module._malloc(rsaSign.privateKeyLength);

		try {
			var returnValue	= Module._crypto_sign_rsasignjs_keypair(
				publicKeyBuffer,
				privateKeyBuffer
			);

			return dataReturn(returnValue, {
				publicKey: dataResult(publicKeyBuffer, rsaSign.publicKeyLength),
				privateKey: dataResult(privateKeyBuffer, rsaSign.privateKeyLength)
			});
		}
		finally {
			dataFree(publicKeyBuffer);
			dataFree(privateKeyBuffer);
		}
	},

	sign: function (message, privateKey) {
		var signedLength		= message.length + rsaSign.signatureLength;

		var signedBuffer		= Module._malloc(signedLength);
		var messageBuffer		= Module._malloc(message.length);
		var privateKeyBuffer	= Module._malloc(rsaSign.privateKeyLength);

		Module.writeArrayToMemory(message, messageBuffer);
		Module.writeArrayToMemory(privateKey, privateKeyBuffer);

		try {
			var returnValue	= Module._crypto_sign_rsaSign(
				signedBuffer,
				0,
				messageBuffer,
				message.length,
				privateKeyBuffer
			);

			return dataReturn(returnValue, dataResult(signedBuffer, signedLength));
		}
		finally {
			dataFree(signedBuffer);
			dataFree(messageBuffer);
			dataFree(privateKeyBuffer);
		}
	},

	signDetached: function (message, privateKey) {
		return new Uint8Array(
			rsaSign.sign(message, privateKey).buffer,
			0,
			rsaSign.signatureLength
		);
	},

	open: function (signed, publicKey) {
		var openedLength	= signed.length - rsaSign.signatureLength;

		var openedBuffer	= Module._malloc(openedLength);
		var signedBuffer	= Module._malloc(signed.length);
		var publicKeyBuffer	= Module._malloc(rsaSign.publicKeyLength);

		Module.writeArrayToMemory(signed, signedBuffer);
		Module.writeArrayToMemory(publicKey, publicKeyBuffer);

		try {
			var returnValue	= Module._crypto_sign_rsasignjs_open(
				openedBuffer,
				0,
				signedBuffer,
				signed.length,
				publicKeyBuffer
			);

			return dataReturn(returnValue, dataResult(openedBuffer, openedLength));
		}
		finally {
			dataFree(openedBuffer);
			dataFree(signedBuffer);
			dataFree(publicKeyBuffer);
		}
	},

	verifyDetached: function (signature, message, publicKey) {
		var signed	= new Uint8Array(rsaSign.signatureLength + message.length);
		signed.set(signature);
		signed.set(message, rsaSign.signatureLength);

		try {
			rsaSign.open(signed, publicKey);
			return true; 
		}
		catch (_) {
			return false;
		}
		finally {
			dataFree(signed);
		}
	}
};



return rsaSign;

}());

self.rsaSign	= rsaSign;

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


Module._rsasignjs_init();


var rsaSign	= {
	publicKeyBytes: Module._rsasignjs_public_key_bytes(),
	privateKeyBytes: Module._rsasignjs_secret_key_bytes(),
	bytes: Module._rsasignjs_signature_bytes(),

	keyPair: function () {
		var publicKeyBuffer		= Module._malloc(rsaSign.publicKeyBytes);
		var privateKeyBuffer	= Module._malloc(rsaSign.privateKeyBytes);

		try {
			var returnValue	= Module._rsasignjs_keypair(
				publicKeyBuffer,
				privateKeyBuffer
			);

			return dataReturn(returnValue, {
				publicKey: dataResult(publicKeyBuffer, rsaSign.publicKeyBytes),
				privateKey: dataResult(privateKeyBuffer, rsaSign.privateKeyBytes)
			});
		}
		finally {
			dataFree(publicKeyBuffer);
			dataFree(privateKeyBuffer);
		}
	},

	sign: function (message, privateKey) {
		var signature	= rsaSign.signDetached(message, privateKey);
		var signed		= new Uint8Array(rsaSign.bytes + message.length);
		signed.set(signature);
		signed.set(message, rsaSign.bytes);
		return signed;
	},

	signDetached: function (message, privateKey) {
		var signatureBuffer		= Module._malloc(rsaSign.bytes);
		var messageBuffer		= Module._malloc(message.length);
		var privateKeyBuffer	= Module._malloc(rsaSign.privateKeyBytes);

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
				dataResult(signatureBuffer, rsaSign.bytes)
			);
		}
		finally {
			dataFree(signatureBuffer);
			dataFree(messageBuffer);
			dataFree(privateKeyBuffer);
		}
	},

	open: function (signed, publicKey) {
		var signature	= new Uint8Array(signed.buffer, 0, rsaSign.bytes);
		var message		= new Uint8Array(signed.buffer, rsaSign.bytes);

		if (rsaSign.verifyDetached(signature, message, publicKey)) {
			return message;
		}
		else {
			dataResult('Invalid signature.');
		}
	},

	verifyDetached: function (signature, message, publicKey) {
		var signatureBuffer	= Module._malloc(rsaSign.bytes);
		var messageBuffer	= Module._malloc(message.length);
		var publicKeyBuffer	= Module._malloc(rsaSign.publicKeyBytes);

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


if (typeof module !== 'undefined' && module.exports) {
	rsaSign.rsaSign	= rsaSign;
	module.exports	= rsaSign;
}
else {
	self.rsaSign	= rsaSign;
}

;

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

function importJWK (key, purpose) {
	return Promise.resolve().then(function () {
		var zeroIndex	= key.indexOf(0);
		var jwk			= JSON.parse(
			sodiumUtil.to_string(
				zeroIndex > -1 ?
					new Uint8Array(new Uint8Array(key).buffer, 0, key.indexOf(0)) :
					new Uint8Array(key)
			)
		);

		return Promise.resolve().then(function () {
			return crypto.subtle.importKey(
				'jwk',
				jwk,
				rsaSign.algorithm,
				false,
				[purpose]
			);
		}).catch(function () {
			return pemJwk.jwk2pem(jwk);
		});
	});
}
	
function exportJWK (key, bytes) {
	return Promise.resolve().then(function () {
		if (typeof key === 'string') {
			return pemJwk.pem2jwk(key);
		}
		else {
			return crypto.subtle.exportKey(
				'jwk',
				key,
				rsaSign.algorithm.name
			);
		}
	}).then(function (jwk) {
		var a	= sodiumUtil.from_string(JSON.stringify(jwk));
		var b	= new Uint8Array(bytes);
		b.set(a);
		sodiumUtil.memzero(a);
		return b;
	});
}


Module._rsasignjs_init();


var rsaSign	= {
	algorithm: isNode ?
		'RSA-SHA256' :
		{
			name: 'RSASSA-PKCS1-v1_5',
			hash: {
				name: 'SHA-256'
			},
			modulusLength: 2048,
			publicExponent: new Uint8Array([0x01, 0x00, 0x01])
		}
	,

	publicKeyBytes: Module._rsasignjs_public_key_bytes(),
	privateKeyBytes: Module._rsasignjs_secret_key_bytes(),
	bytes: Module._rsasignjs_signature_bytes(),

	keyPair: function () {
		return Promise.resolve().then(function () {
			if (isNode) {
				var keyPair	= rsaKeygen.generate();

				return {
					publicKey: keyPair.public_key.toString(),
					privateKey: keyPair.private_key.toString()
				};
			}
			else {
				return crypto.subtle.generateKey(
					rsaSign.algorithm,
					true,
					['sign', 'verify']
				);
			}
		}).catch(function () {
			var publicKeyBuffer		= Module._malloc(rsaSign.publicKeyBytes);
			var privateKeyBuffer	= Module._malloc(rsaSign.privateKeyBytes);

			try {
				var returnValue	= Module._rsasignjs_keypair(
					publicKeyBuffer,
					privateKeyBuffer
				);

				if (returnValue !== 0) {
					throw new Error('RSA Sign error: keyPair failed (' + returnValue + ')');
				}

				return {
					publicKey:
						'-----BEGIN PUBLIC KEY-----\n' +
						sodiumUtil.to_base64(dataResult(publicKeyBuffer, rsaSign.publicKeyBytes)) +
						'\n-----END PUBLIC KEY-----'
					,
					privateKey:
						'-----BEGIN RSA PRIVATE KEY-----\n' +
						sodiumUtil.to_base64(dataResult(privateKeyBuffer, rsaSign.privateKeyBytes)) +
						'\n-----END RSA PRIVATE KEY-----'
				};
			}
			finally {
				dataFree(publicKeyBuffer, rsaSign.publicKeyBytes);
				dataFree(privateKeyBuffer, rsaSign.privateKeyBytes);
			}
		}).then(function (keyPair) {
			return Promise.all([
				exportJWK(keyPair.publicKey, rsaSign.publicKeyBytes),
				exportJWK(keyPair.privateKey, rsaSign.privateKeyBytes)
			]);
		}).then(function (results) {
			return {
				publicKey: results[0],
				privateKey: results[1]
			};
		});
	},

	sign: function (message, privateKey) {
		return rsaSign.signDetached(message, privateKey).then(function (signature) {
			var signed	= new Uint8Array(rsaSign.bytes + message.length);
			signed.set(signature);
			signed.set(message, rsaSign.bytes);
			return signed;
		});
	},

	signDetached: function (message, privateKey) {
		return importJWK(privateKey, 'sign').then(function (sk) {
			return Promise.resolve().then(function () {
				if (isNode) {
					var messageBuffer	= new Buffer(message);
					var signer			= nodeCrypto.createSign(rsaSign.algorithm);
					signer.write(messageBuffer);
					signer.end();

					var signature	= signer.sign(sk);
					sodiumUtil.memzero(messageBuffer);
					return signature;
				}
				else {
					return crypto.subtle.sign(rsaSign.algorithm, sk, message);
				}
			}).catch(function () {
				sk	= sodiumUtil.from_base64(sk.split('-----')[2]);

				var signatureBuffer		= Module._malloc(rsaSign.bytes);
				var messageBuffer		= Module._malloc(message.length);
				var privateKeyBuffer	= Module._malloc(sk.length);

				Module.writeArrayToMemory(message, messageBuffer);
				Module.writeArrayToMemory(sk, privateKeyBuffer);

				try {
					var returnValue	= Module._rsasignjs_sign(
						signatureBuffer,
						messageBuffer,
						message.length,
						privateKeyBuffer,
						sk.length
					);

					if (returnValue !== 1) {
						throw new Error('RSA Sign error: sign failed (' + returnValue + ')');
					}

					return dataResult(signatureBuffer, rsaSign.bytes);
				}
				finally {
					dataFree(signatureBuffer);
					dataFree(messageBuffer);
					dataFree(privateKeyBuffer);
				}
			}).then(function (signature) {
				sodiumUtil.memzero(sk);
				return new Uint8Array(signature);
			});
		});
	},

	open: function (signed, publicKey) {
		return Promise.resolve().then(function () {
			var signature	= new Uint8Array(signed.buffer, 0, rsaSign.bytes);
			var message		= new Uint8Array(signed.buffer, rsaSign.bytes);

			return rsaSign.verifyDetached(signature, message, publicKey).then(function (isValid) {
				if (isValid) {
					return message;
				}
				else {
					throw new Error('Failed to open RSA signed message.');
				}
			});
		});
	},

	verifyDetached: function (signature, message, publicKey) {
		return importJWK(publicKey, 'verify').then(function (pk) {
			return Promise.resolve().then(function () {
				if (isNode) {
					var verifier	= nodeCrypto.createVerify(rsaSign.algorithm);
					verifier.update(new Buffer(message));
					return verifier.verify(pk, signature);
				}
				else {
					return crypto.subtle.verify(rsaSign.algorithm, pk, signature, message);
				}
			}).catch(function () {
				pk	= sodiumUtil.from_base64(pk.split('-----')[2]);

				var signatureBuffer	= Module._malloc(rsaSign.bytes);
				var messageBuffer	= Module._malloc(message.length);
				var publicKeyBuffer	= Module._malloc(pk.length);

				Module.writeArrayToMemory(signature, signatureBuffer);
				Module.writeArrayToMemory(message, messageBuffer);
				Module.writeArrayToMemory(pk, publicKeyBuffer);

				try {
					var returnValue	= Module._rsasignjs_verify(
						signatureBuffer,
						messageBuffer,
						message.length,
						publicKeyBuffer,
						pk.length
					);

					return returnValue === 1;
				}
				finally {
					dataFree(signatureBuffer);
					dataFree(messageBuffer);
					dataFree(publicKeyBuffer);
				}
			}).then(function (isValid) {
				sodiumUtil.memzero(pk);
				return isValid;
			});
		});
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


}());

var Module	= {};

var isNode	=
	typeof process === 'object' &&
	typeof require === 'function' &&
	typeof window !== 'object' &&
	typeof importScripts !== 'function'
;


var pemJwk		= require('pem-jwk-norecompute');
var sodiumUtil	= require('sodiumutil');


var nodeCrypto, generateRSAKeypair;
if (isNode) {
	nodeCrypto			= require('crypto');
	generateRSAKeypair	= require('generate-rsa-keypair');
}
else {

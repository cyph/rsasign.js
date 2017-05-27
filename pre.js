(function () {


var isNode	=
	typeof process === 'object' &&
	typeof require === 'function' &&
	typeof window !== 'object' &&
	typeof importScripts !== 'function'
;


var pemJwk		= require('pem-jwk-norecompute');
var sodiumUtil	= require('sodiumutil');


var rsaSign = (function () {

if (isNode) {
	self		= this;

	/* Workaround to avoid detection by webpack */
	rsaKeygen	= eval('require')('rsa-keygen');
}

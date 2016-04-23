all:
	rm -rf dist libsodium openssl 2> /dev/null
	mkdir dist

	git clone -b stable https://github.com/jedisct1/libsodium.git
	cd libsodium ; emconfigure ./configure --enable-minimal --disable-shared

	git clone -b OpenSSL_1_0_2-stable https://github.com/openssl/openssl.git
	cd openssl ; emconfigure ./config

	bash -c ' \
		args="$$(echo " \
			--memory-init-file 0 \
			-DOPENSSL_FIPS \
			-s TOTAL_MEMORY=104900000 -s TOTAL_STACK=52443072 \
			-s NO_DYNAMIC_EXECUTION=1 -s RUNNING_JS_OPTS=1 -s ASSERTIONS=0 \
			-s AGGRESSIVE_VARIABLE_ELIMINATION=1 -s ALIASING_FUNCTION_POINTERS=1 \
			-s FUNCTION_POINTER_ALIGNMENT=1 -s DISABLE_EXCEPTION_CATCHING=1 \
			 -s RESERVED_FUNCTION_POINTERS=8 -s NO_FILESYSTEM=1 \
			-Ilibsodium/src/libsodium/include/sodium \
			-Iopenssl -Iopenssl/include -Iopenssl/crypto \
			libsodium/src/libsodium/randombytes/randombytes.c \
			openssl/crypto/rsa/rsa_sign.c \
			rsasign.c \
			-s EXPORTED_FUNCTIONS=\"[ \
				'"'"'_rsasignjs_init'"'"', \
				'"'"'_rsasignjs_keypair'"'"', \
				'"'"'_rsasignjs_sign'"'"', \
				'"'"'_rsasignjs_verify'"'"', \
				'"'"'_rsasignjs_public_key_bytes'"'"', \
				'"'"'_rsasignjs_secret_key_bytes'"'"', \
				'"'"'_rsasignjs_signature_bytes'"'"' \
			]\" \
			--pre-js pre.js --post-js post.js \
		" | perl -pe "s/\s+/ /g" | perl -pe "s/\[ /\[/g" | perl -pe "s/ \]/\]/g")"; \
		\
		bash -c "emcc -O3 $$args -o dist/rsa-sign.js"; \
		bash -c "emcc -O0 -g4 $$args -o dist/rsa-sign.debug.js"; \
	'

	rm -rf libsodium openssl

clean:
	rm -rf dist libsodium openssl

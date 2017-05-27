all:
	rm -rf dist libsodium node_modules openssl 2> /dev/null
	mkdir dist node_modules

	npm install

	git clone --depth 1 -b stable https://github.com/jedisct1/libsodium
	cd libsodium ; emconfigure ./configure --enable-minimal --disable-shared

	git clone --depth 1 -b OpenSSL_1_1_0-stable https://github.com/openssl/openssl
	cd openssl ; emconfigure perl Configure -static no-afalgeng no-asan no-asm no-async no-autoalginit no-autoerrinit no-bf no-blake2 no-camellia no-capieng no-cast no-chacha no-cmac no-cms no-comp no-crypto-mdebug no-crypto-mdebug-backtrace no-ct no-deprecated no-des no-dgram no-dh no-dsa no-dso no-dtls no-dynamic-engine no-ec no-ec2m no-ecdh no-ecdsa no-ec_nistp_64_gcc_128 no-egd no-engine no-err no-filenames no-fuzz-libfuzzer no-fuzz-afl no-gost no-heartbeats no-hw no-idea no-makedepend no-md2 no-md4 no-mdc2 no-msan no-multiblock no-nextprotoneg no-ocb no-ocsp no-pic no-poly1305 no-posix-io no-psk no-rc2 no-rc4 no-rc5 no-rdrand no-rfc3779 no-rmd160 no-scrypt no-sctp no-seed no-shared no-sock no-srp no-srtp no-sse2 no-ssl no-ssl-trace no-static-engine no-stdio no-threads no-tls no-ts no-ubsan no-ui no-unit-test no-whirlpool no-weak-ssl-ciphers no-zlib no-zlib-dynamic linux-generic32 ; sed -i 's|$$(CROSS_COMPILE)/home/|/home/|g' Makefile ; make build_libs

	bash -c ' \
		args="$$(echo " \
			--memory-init-file 0 \
			-DRSASIGNJS_BITS=2048 -DRSASIGNJS_PUBLEN=450 -DRSASIGNJS_PRIVLEN=1700 -DRSASIGNJS_SIGLEN=256 \
			-s TOTAL_MEMORY=16777216 -s TOTAL_STACK=8388608 \
			-s NO_DYNAMIC_EXECUTION=1 -s RUNNING_JS_OPTS=1 -s ASSERTIONS=0 \
			-s AGGRESSIVE_VARIABLE_ELIMINATION=1 -s ALIASING_FUNCTION_POINTERS=1 \
			-s FUNCTION_POINTER_ALIGNMENT=1 -s DISABLE_EXCEPTION_CATCHING=1 \
			 -s RESERVED_FUNCTION_POINTERS=8 -s NO_FILESYSTEM=1 \
			-Ilibsodium/src/libsodium/include/sodium \
			-Iopenssl -Iopenssl/include -Iopenssl/crypto \
			libsodium/src/libsodium/randombytes/randombytes.c \
			openssl/crypto/rand/rand_err.o \
			$$(find openssl/crypto -type f -name "*.o" -not -path "openssl/crypto/rand/*" | tr "\n" " ") \
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
		bash -c "emcc -Oz $$args -o dist/rsasign.module.js"; \
		bash -c "emcc -O0 -g4 $$args -o dist/rsasign.debug.js"; \
	'

	sed -i 's|require(|eval("require")(|g' dist/rsasign.module.js
	sed -i 's|eval("require")("pem-jwk-norecompute")|require("pem-jwk-norecompute")|g' dist/rsasign.module.js
	sed -i 's|eval("require")("sodiumutil")|require("sodiumutil")|g' dist/rsasign.module.js

	webpack --output-library-target var --output-library rsaSign dist/rsasign.module.js dist/rsasign.js
	uglifyjs dist/rsasign.js -o dist/rsasign.js

	rm -rf libsodium node_modules openssl

clean:
	rm -rf dist libsodium node_modules openssl

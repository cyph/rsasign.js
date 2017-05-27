all:
	rm -rf dist libsodium node_modules openssl 2> /dev/null
	mkdir dist node_modules

	npm install

	git clone --depth 1 -b stable https://github.com/jedisct1/libsodium
	cd libsodium ; emconfigure ./configure --enable-minimal --disable-shared

	git clone --depth 1 -b OpenSSL_1_1_0-stable https://github.com/openssl/openssl
	cd openssl ; emconfigure perl Configure no-asm no-engine no-hw no-threads no-shared no-dso no-sse2 no-ec2m linux-generic32 ; sed -i 's|$$(CROSS_COMPILE)/home/|/home/|g' Makefile ; make

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
		bash -c "emcc -O3 $$args -o dist/rsasign.js"; \
		bash -c "emcc -O0 -g4 $$args -o dist/rsasign.debug.js"; \
	'

	sed -i 's|require(|eval("require")(|g' dist/rsasign.js
	sed -i 's|eval("require")("pem-jwk-norecompute")|require("pem-jwk-norecompute")|g' dist/rsasign.js
	sed -i 's|eval("require")("sodiumutil")|require("sodiumutil")|g' dist/rsasign.js

	webpack --output-library-target var --output-library rsaSign dist/rsasign.js dist/rsasign.global.js
	uglifyjs dist/rsasign.global.js -o dist/rsasign.global.js

	rm -rf libsodium node_modules openssl

clean:
	rm -rf dist libsodium node_modules openssl

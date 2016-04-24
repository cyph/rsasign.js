all:
	rm -rf dist openssl 2> /dev/null
	mkdir dist

	git clone -b stable https://github.com/jedisct1/libsodium.git
	cd libsodium ; emconfigure ./configure --enable-minimal --disable-shared

	git clone -b OpenSSL_1_0_2-stable https://github.com/openssl/openssl.git
	cd openssl ; emconfigure ./config no-asm no-threads no-shared no-dso no-sse2 no-ec2m ; sed -i 's|CC= $(CROSS_COMPILE)|CC=|g' Makefile ; sed -i 's|-arch i386||g' Makefile ; make

	bash -c ' \
		args="$$(echo " \
			--memory-init-file 0 \
			-DRSASIGNJS_BITS=2048 -DRSASIGNJS_PUBLEN=300 -DRSASIGNJS_PRIVLEN=1200 -DRSASIGNJS_SIGLEN=512 \
			-s TOTAL_MEMORY=117440512 -s TOTAL_STACK=52443072 \
			-s NO_DYNAMIC_EXECUTION=1 -s RUNNING_JS_OPTS=1 -s ASSERTIONS=0 \
			-s AGGRESSIVE_VARIABLE_ELIMINATION=1 -s ALIASING_FUNCTION_POINTERS=1 \
			-s FUNCTION_POINTER_ALIGNMENT=1 -s DISABLE_EXCEPTION_CATCHING=1 \
			 -s RESERVED_FUNCTION_POINTERS=8 -s NO_FILESYSTEM=1 \
			-Ilibsodium/src/libsodium/include/sodium \
			-Iopenssl -Iopenssl/include -Iopenssl/fips -Iopenssl/crypto \
			libsodium/src/libsodium/randombytes/randombytes.c \
			openssl/crypto/*.o \
			openssl/crypto/err/*.o \
			openssl/crypto/stack/*.o \
			openssl/crypto/lhash/*.o \
			openssl/crypto/bio/*.o \
			openssl/crypto/objects/*.o \
			openssl/crypto/buffer/*.o \
			openssl/crypto/engine/*.o \
			openssl/crypto/evp/*.o \
			openssl/crypto/x509v3/*.o \
			openssl/crypto/pkcs7/*.o \
			openssl/crypto/cmac/*.o \
			openssl/crypto/hmac/*.o \
			openssl/crypto/cms/*.o \
			openssl/crypto/ecdh/*.o \
			openssl/crypto/ecdsa/*.o \
			openssl/crypto/ec/*.o \
			openssl/crypto/dsa/*.o \
			openssl/crypto/dh/*.o \
			openssl/crypto/sha/*.o \
			openssl/crypto/bn/*.o \
			openssl/crypto/asn1/*.o \
			openssl/crypto/rsa/*.o \
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

	rm -rf openssl

clean:
	rm -rf dist openssl

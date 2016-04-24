all:
	rm -rf dist openssl 2> /dev/null
	mkdir dist

	git clone -b OpenSSL-fips-2_0-stable https://github.com/openssl/openssl.git
	cd openssl ; export FIPS_AUTH_KEY='"test"' ; export FIPS_AUTH_OFFICER='"test"' ; export FIPS_AUTH_USER='"test"' ; emconfigure ./config no-asm no-threads no-shared no-dso no-sse2 no-ec2m fipscanisterbuild ; sed -i 's|CC= $(CROSS_COMPILE)|CC=|g' Makefile ; sed -i 's|-arch i386||g' Makefile ; make

	bash -c ' \
		args="$$(echo " \
			--memory-init-file 0 \
			-DRSASIGNJS_BITS=2048 -DRSASIGNJS_PUBLEN=526 -DRSASIGNJS_PRIVLEN=1500 -DRSASIGNJS_SIGLEN=512 \
			-DOPENSSL_FIPS \
			-s TOTAL_MEMORY=104900000 -s TOTAL_STACK=52443072 \
			-s NO_DYNAMIC_EXECUTION=1 -s RUNNING_JS_OPTS=1 -s ASSERTIONS=0 \
			-s AGGRESSIVE_VARIABLE_ELIMINATION=1 -s ALIASING_FUNCTION_POINTERS=1 \
			-s FUNCTION_POINTER_ALIGNMENT=1 -s DISABLE_EXCEPTION_CATCHING=1 \
			 -s RESERVED_FUNCTION_POINTERS=8 -s NO_FILESYSTEM=1 \
			-Iopenssl -Iopenssl/include -Iopenssl/fips -Iopenssl/crypto \
			openssl/fips/fipscanister.o \
			rsasign.helper.c \
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

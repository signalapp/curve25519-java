
ed:
	gcc -O3 -Wall ed25519/*.c ed25519/main/main.c ed25519/tests/*.c ed25519/additions/*.c ed25519/additions/generalized/*.c ed25519/nacl_sha512/*.c \
  -Ied25519/nacl_includes -Ied25519/additions -Ied25519/additions/generalized -Ied25519/tests -Ied25519 -o ed

make clean:
	rm -f ed


# DO NOT USE THIS YET

## Generating a Curve25519 keypair:

```
SecureRandom      secureRandom = SecureRandom.getInstance("SHA1PRNG");
Curve25519KeyPair keyPair      = Curve25519.generateKeyPair();
```

## Calculating a shared secret:

```
byte[] sharedSecret = Curve25519.calculateAgreement(publicKey, privateKey);
```

## Calculating a signature:

```
SecureRandom secureRandom = SecureRandom.getInstance("SHA1PRNG");
byte[]       signature    = Curve25519.calculateSignature(secureRandom, privateKey, message);
```

## Verifying a signature:

```
boolean validSignature = Curve25519.verifySignature(publicKey, message, signature);
```
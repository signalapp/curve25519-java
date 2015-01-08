# curve25519-java

A Java Curve25519 implementation that is backed by native code when available, and
pure Java when a native library is not available.

## Installing

To use on Android:

```
dependencies {
  compile 'org.whispersystems:curve25519-android:(latest version number here)'
}
```

To use from pure Java:

```
<dependency>
  <groupId>org.whispersystems</groupId>
  <artifactId>curve25519-java</artifactId>
  <version>(latest version number here)</version>
</dependency>
```

The Android artifact is an AAR that contains an NDK-backed native implementation, while
the Java artifact is a JAR that only contains the pure-Java Curve25519 provider.

## Using

### Generating a Curve25519 keypair:

```
SecureRandom      secureRandom = SecureRandom.getInstance("SHA1PRNG");
Curve25519KeyPair keyPair      = Curve25519.generateKeyPair(secureRandom);
```

### Calculating a shared secret:

```
byte[] sharedSecret = Curve25519.calculateAgreement(publicKey, privateKey);
```

### Calculating a signature:

```
SecureRandom secureRandom = SecureRandom.getInstance("SHA1PRNG");
byte[]       signature    = Curve25519.calculateSignature(secureRandom, privateKey, message);
```

### Verifying a signature:

```
boolean validSignature = Curve25519.verifySignature(publicKey, message, signature);
```

## License

Copyright 2015 Open Whisper Systems

Licensed under the GPLv3: http://www.gnu.org/licenses/gpl-3.0.html

# curve25519-java

A Java Curve25519 implementation that is backed by native code when available, and
pure Java when a native library is not available. There is also a J2ME build variant.

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

To use from J2ME:

```
<dependency>
  <groupId>org.whispersystems</groupId>
  <artifactId>curve25519-j2me</artifactId>
  <version>(latest version number here)</version>
</dependency>
```


The Android artifact is an AAR that contains an NDK-backed native implementation, while
the Java artifact is a JAR that only contains the pure-Java Curve25519 provider.

## Using

## Obtaining an instance

The caller needs to specify a `provider` when obtaining a Curve25519 instance.  There are
four built in providers:

1. `Curve25519.NATIVE` -- This is a JNI backed provider.
1. `Curve25519.JAVA` -- This is a pure Java 7 backed provider.
1. `Curve25519.J2ME` -- This is a J2ME compatible provider.
1. `Curve25519.BEST` -- This is a provider that attempts to use `NATIVE`,
   but falls back to `JAVA` if the former is unavailable.

The caller specifies a provider during instance creation:

```
Curve25519 cipher = Curve25519.getInstance(Curve25519.BEST);
```

Since J2ME doesn't have built-in `SecureRandom` support, J2ME users need to supply their
own source of `SecureRandom` by implementing the `SecureRandomProvider` interface and
passing it in:

```
Curve25519 cipher = Curve25519.getInstance(Curve25519.J2ME, new MySecureRandomProvider());
```

### Generating a Curve25519 keypair:

```
Curve25519KeyPair keyPair = Curve25519.getInstance(Curve25519.BEST).generateKeyPair();
```

### Calculating a shared secret:

```
Curve25519 cipher       = Curve25519.getInstance(Curve25519.BEST);
byte[]     sharedSecret = cipher.calculateAgreement(publicKey, privateKey);
```

### Calculating a signature:

```
Curve25519 cipher    = Curve25519.getInstance(Curve25519.BEST);
byte[]     signature = cipher.calculateSignature(secureRandom, privateKey, message);
```

### Verifying a signature:

```
Curve25519 cipher         = Curve25519.getInstance(Curve25519.BEST);
boolean    validSignature = cipher.verifySignature(publicKey, message, signature);
```

## License

Copyright 2013-2019 Open Whisper Systems

Licensed under the GPLv3: http://www.gnu.org/licenses/gpl-3.0.html

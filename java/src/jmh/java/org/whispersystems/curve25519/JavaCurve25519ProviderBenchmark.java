package org.whispersystems.curve25519;

import org.openjdk.jmh.annotations.*;
import org.openjdk.jmh.infra.Blackhole;

import java.util.Random;
import java.util.concurrent.TimeUnit;

@OutputTimeUnit(TimeUnit.MICROSECONDS)
@BenchmarkMode(Mode.AverageTime)
@Threads(4)
@Fork(1)
@Warmup(iterations = 10)
@Measurement(iterations = 5)
public class JavaCurve25519ProviderBenchmark {
    @State(Scope.Thread)
    public static class BenchmarkState {
        public JavaCurve25519Provider provider = new JavaCurve25519Provider();
        public byte[] privateKey;
        public byte[] publicKey;
        public byte[] random = new byte[64];
        public byte[] message = new byte[256];
        public byte[] editedMessage = new byte[256];
        public byte[] signature;
        public byte[] vrfSignature;

        @Setup(Level.Iteration)
        public void doSetup() {
            Random r = new Random();
            r.nextBytes(random);
            r.nextBytes(message);
            System.arraycopy(message, 0, editedMessage, 0, 256);
            // invert 1 byte
            editedMessage[0] ^= 0xff;
            privateKey = provider.generatePrivateKey(random);
            publicKey = provider.generatePublicKey(privateKey);
            signature = provider.calculateSignature(random, privateKey, message);
            vrfSignature = provider.calculateVrfSignature(random, privateKey, message);
        }
    }

    @Benchmark
    public void generatePrivateKey(Blackhole blackhole, BenchmarkState bs) {
        blackhole.consume(bs.provider.generatePrivateKey());
    }

    @Benchmark
    public void generatePrivateKeyWithRandom(Blackhole blackhole, BenchmarkState bs) {
        blackhole.consume(bs.provider.generatePrivateKey(bs.random));
    }

    @Benchmark
    public void generatePublicKey(Blackhole blackhole, BenchmarkState bs) {
        blackhole.consume(bs.provider.generatePublicKey(bs.privateKey));
    }

    @Benchmark
    public void calculateSignature(Blackhole blackhole, BenchmarkState bs) {
        blackhole.consume(bs.provider.calculateSignature(bs.random, bs.privateKey, bs.message));
    }

    @Benchmark
    public void verifyValidSignature(Blackhole blackhole, BenchmarkState bs) {
        blackhole.consume(bs.provider.verifySignature(bs.publicKey, bs.message, bs.signature));
    }

    @Benchmark
    public void verifyInvalidSignature(Blackhole blackhole, BenchmarkState bs) {
        blackhole.consume(bs.provider.verifySignature(bs.publicKey, bs.editedMessage, bs.signature));
    }

    @Benchmark
    public void calculateVRFSignature(Blackhole blackhole, BenchmarkState bs) {
        blackhole.consume(bs.provider.calculateVrfSignature(bs.random, bs.privateKey, bs.message));
    }

    @Benchmark
    public void verifyValidVrfSignature(Blackhole blackhole, BenchmarkState bs) throws VrfSignatureVerificationFailedException {
        blackhole.consume(bs.provider.verifyVrfSignature(bs.publicKey, bs.message, bs.vrfSignature));
    }

    @Benchmark
    public void verifyInvalidVrfSignature(Blackhole blackhole, BenchmarkState bs) {
        try {
            blackhole.consume(bs.provider.verifyVrfSignature(bs.publicKey, bs.editedMessage, bs.vrfSignature));
        } catch (VrfSignatureVerificationFailedException ignored) {}
    }
}

## TimW Bouncy Castle contributions

This is a fork of the [official Bouncy Castle](https://github.com/bcgit/bc-java) GitHub mirror used to track my contributions.

Pending contributions are in feature branches, accepted contributions live on only as tags.

### Proposed

#### [Stream Cipher Reset Testing](https://github.com/timw/bc-java/commits/feature/stream-cipher-reset) (28 July 2013)

[pull request](https://github.com/bcgit/bc-java/pull/31)

* Tests for reset of stream ciphers on encrypt/decrypt, init and reset operations.
* Minor fixes for Grain\* and HC\* ciphers to make them reset properly on subsequent inits.


#### [CipherInputStream Improvements](https://github.com/timw/bc-java/commits/feature/cipher-input-stream) (28 July 2013)

[pull request](https://github.com/bcgit/bc-java/pull/32)

Two parts to this:

1.  rewrites of JCE javax.crypto.CipherInputStream and CipherOutputStream that don't silently eat invalid ciphertext exceptions and don't call doFinal() twice (i.e. can be used and used safely with AEAD ciphers). See links below for issues with javax.crypto versions.
2. improvement to LW API CipherInputStream and CipherOutputStream to support AEADBlockCiphers and simplify internal logic.

Full testing of JCE and LW Cipher streams with common ciphers is included, including tampering of AEAD ciphertexts.

Oracle bug refs for broken Cipher stream behaviour:
 - http://bugs.sun.com/bugdatabase/view_bug.do?bug_id=8016171 (CipherInputStream masks ciphertext tampering with AEAD ciphers in decrypt mode)
 - http://bugs.sun.com/bugdatabase/view_bug.do?bug_id=8016249 (CipherInputStream in decrypt mode fails on close with AEAD ciphers)
 - http://bugs.sun.com/bugdatabase/view_bug.do?bug_id=8012900 (CICO ignores AAD in GCM mode)

### [JCE AAD API support](https://github.com/timw/bc-java/commits/feature/aad-api) (July 3 2013)

[pull request](https://github.com/bcgit/bc-java/pull/31)

* Add Java 7 JCE AAD support to BouncyCastle JCE provider (`Cipher.updateAAD()` and `GCMParameterSpec`).
* Residual of previous contribution (in CVS days) to add online/incremental AAD processing to `AEADBlockCipher`.

### In Progress


### Accepted

#### [XSalsa20, ChaCha](https://github.com/timw/bc-java/commits/contrib/xsalsa20) (July 9 2013)

[pull request](https://github.com/bcgit/bc-java/pull/20)

XSalsa20 implementation, based on the existing Salsa20 engine with a couple of tweaks to allow the key setup and nonce size to vary

XSalsa20 is a version of the Salsa20 stream cipher with an extended (192 vs 64 bit) nonce.

Test vectors are copied from the [cryptopp implementation](https://github.com/murrificus/cryptopp/blob/master/src/TestVectors/salsa.txt), which were generated using the nacl XSalsa20. There don't appear to be any official test vectors.

--- 
ChaCha implementation, based on the existing Salsa20 engine with the key setup, block permutation and block counter increment overridden.

This is basically an implementation of the 'regs' reference implementation found in the eStream benchmark suite and at http://cr.yp.to/chacha.html.

Speed is slightly (~10% faster) than the Salsa20 engine (due to the registerization).

---
Reduced round Salsa20

Parameterisation of Salsa20Engine to allow arbitrary rounds. Test vectors from estreambench-20080905.

---
Registerization of Salsa20Engine

Registerize the state variables in salsa20Core to allow Hotspot etc. to optimise the loads/stores (as much as can be done with 16 variables and no SIMD).
Boosts performance by about 10% on common x86 hardware, possibly more on setups with more registers. Should have no affect on systems with small numbers of registers.

#### [Reset and Tamper Testing for AEAD](https://github.com/timw/bc-java/tree/contrib/aead-tamper-testing) (July 3 2013)

[pull request](https://github.com/bcgit/bc-java/pull/12)

* Unit tests that exercise state resets for encrypt/decrypt, init and reset operations, and for various ways of tampering with AEAD ciphertexts.
* Fixes for CCM and EAX mode issues revealed by testing.

#### [Threefish and Skein](https://github.com/timw/bc-java/tree/contrib/threefish-skein) (July 3 2013)

[pull request](https://github.com/bcgit/bc-java/pull/9)

* Threefish, Skein, Skein-MAC + HMAC-Skein in 256, 512, 1024 bit block sizes.
* JCE registrations for all of these algos with standard output sizes (for digest + MAC).

### Experimental Stuff

#### [Simon and Speck Ciphers](https://github.com/timw/bc-java/commits/feature/simon-speck) (24 July 2013)
  
* Implementation of the [Simon and Speck families of lightweight block ciphers](http://eprint.iacr.org/2013/404).
* All block/key size variants are implemented, with JCE registrations and tests against published test vectors.

Speck in 32/64 bit word variants performs well in Java, although slower than Threefish due to the smaller block sizes.
Community cryptanalysis of Simon/Speck is at a very early stage, so not proposing this for BC at present.

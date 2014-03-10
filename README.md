## TimW Bouncy Castle contributions

This is a fork of the [official Bouncy Castle](https://github.com/bcgit/bc-java) GitHub mirror used to track my contributions.

Pending contributions are in feature branches, accepted contributions live on only as tags.

### Proposed

### In Progress

### Experimental Stuff

#### [Simon and Speck Ciphers](https://github.com/timw/bc-java/commits/feature/simon-speck) (24 July 2013)
  
* Implementation of the [Simon and Speck families of lightweight block ciphers](http://eprint.iacr.org/2013/404).
* All block/key size variants are implemented, with JCE registrations and tests against published test vectors.

Speck in 32/64 bit word variants performs well in Java, although slower than Threefish due to the smaller block sizes.
Community cryptanalysis of Simon/Speck is at a very early stage, so not proposing this for BC at present.

### Accepted

#### [Include ChaCha in regression tests](https://github.com/timw/bc-java/tree/contrib/chacha-in-regression) (October 20 2013)

[pull request](https://github.com/bcgit/bc-java/pull/40)

* Include ChaChaTest in cipher RegressionTest, plus a minor typo in ChaChaTest.

#### [Reduce data copying in CCM mode](https://github.com/timw/bc-java/tree/contrib/ccm-no-copy) (September 7 2013)

[pull request](https://github.com/bcgit/bc-java/pull/34)

Remove unnecessary data copying in the CCM mode implementation:

* ByteArrayOutputStream buffers for AD and data are accessed directly to avoid extra allocate+copy of each
* The output buffer is used directly by processPacket output without allocate+copy of a temporary buffer

#### [CipherInputStream Improvements](https://github.com/timw/bc-java/tree/contrib/cipher-input-stream) (28 July 2013)

[pull request](https://github.com/bcgit/bc-java/pull/32)

Two parts to this:

1.  rewrites of JCE javax.crypto.CipherInputStream and CipherOutputStream that don't silently eat invalid ciphertext exceptions and don't call doFinal() twice (i.e. can be used and used safely with AEAD ciphers). See links below for issues with javax.crypto versions.
2. improvement to LW API CipherInputStream and CipherOutputStream to support AEADBlockCiphers and simplify internal logic.

Full testing of JCE and LW Cipher streams with common ciphers is included, including tampering of AEAD ciphertexts.

Oracle bug refs for broken Cipher stream behaviour:
 - http://bugs.sun.com/bugdatabase/view_bug.do?bug_id=8016171 (CipherInputStream masks ciphertext tampering with AEAD ciphers in decrypt mode)
 - http://bugs.sun.com/bugdatabase/view_bug.do?bug_id=8016249 (CipherInputStream in decrypt mode fails on close with AEAD ciphers)
 - http://bugs.sun.com/bugdatabase/view_bug.do?bug_id=8012900 (CICO ignores AAD in GCM mode)

#### [Stream Cipher Reset Testing](https://github.com/timw/bc-java/tree/contrib/stream-cipher-reset) (28 July 2013)

[pull request](https://github.com/bcgit/bc-java/pull/31)

* Tests for reset of stream ciphers on encrypt/decrypt, init and reset operations.
* Minor fixes for Grain\* and HC\* ciphers to make them reset properly on subsequent inits.

#### [Missing algorithms in specifications](https://github.com/timw/bc-java/tree/contrib/jce-registrations) (July 24 2013)

[pull request](https://github.com/bcgit/bc-java/pull/28)

* Document various algorithms that have been missed/misrepresented in the specs.

#### [Fast Poly1305 Mac Implementation](https://github.com/timw/bc-java/tree/contrib/poly1305) (July 17 2013)

[pull request](https://github.com/bcgit/bc-java/pull/27)

* Fast implementation of Poly1305 message authentication code, with tests and JCE registrations.
* The fast polynomial calculation in this implementation is adapted from the public domain 'poly1305-donna-unrolled' C implementation by Andrew M (@floodyberry) (https://github.com/floodyberry/poly1305-donna) - primarily adapting to Java signed integer arithmetic.
* JCE registrations are provided for Poly1305-* for 128 bit AES era block ciphers (AES, Serpent, Twofish etc.)

#### [Exception testing for CTS mode](https://github.com/timw/bc-java/tree/contrib/cts-exceptions) (July 17 2013)

[pull request](https://github.com/bcgit/bc-java/pull/26)

* Add exception testing (as already exist for other modes) for CTS mode.
* Fix a couple of minor issues arising from those tests.

#### [XSalsa20, ChaCha, Reduced Round Salsa20](https://github.com/timw/bc-java/commits/contrib/xsalsa20) (July 9 2013)

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

#### [Correct length of JCE automatic IV for OCB](https://github.com/timw/bc-java/tree/contrib/jce-ocb-nonce) (July 4 2013)

[pull request](https://github.com/bcgit/bc-java/pull/18)

* Generate 120 bit nonces for OCB in JCE API.

#### [Correct length of JCE automatic IV for CCM](https://github.com/timw/bc-java/tree/contrib/jce-ccm-nonce) (July 4 2013)

[pull request](https://github.com/bcgit/bc-java/pull/17)

* Generate 13 byte nonces for CCM in JCE API.

#### [CAST6/Noekeon with OCB mode in JCE](https://github.com/timw/bc-java/tree/contrib/ocb-cast6-noekeon) (July 4 2013)

[pull request](https://github.com/bcgit/bc-java/pull/16)

* When used via JCE, OCB mode requires a BlockCipherProvider (since it uses two instances of a block cipher), so implement this for CAST6/Noekeon.

#### [Prevent CMAC from accepting IV](https://github.com/timw/bc-java/tree/contrib/cmac-no-iv) (July 4 2013)

[pull request](https://github.com/bcgit/bc-java/pull/14)

* CMAC is defined with an all zero IV (Page 9 of NIST SP 800-38B), so block any init parameters other than KeyParameter being passed to underlying CBC mode..

#### [JCE AAD API support](https://github.com/timw/bc-java/tree/contrib/aad-api) (July 3 2013)

[pull request](https://github.com/bcgit/bc-java/pull/11)

* Add Java 7 JCE AAD support to BouncyCastle JCE provider (`Cipher.updateAAD()` and `GCMParameterSpec`).
* Residual of previous contribution (in CVS days) to add online/incremental AAD processing to `AEADBlockCipher`.

#### [Reset and Tamper Testing for AEAD](https://github.com/timw/bc-java/tree/contrib/aead-tamper-testing) (July 3 2013)

[pull request](https://github.com/bcgit/bc-java/pull/12)

* Unit tests that exercise state resets for encrypt/decrypt, init and reset operations, and for various ways of tampering with AEAD ciphertexts.
* Fixes for CCM and EAX mode issues revealed by testing.

#### [Threefish and Skein](https://github.com/timw/bc-java/tree/contrib/threefish-skein) (July 3 2013)

[pull request](https://github.com/bcgit/bc-java/pull/9)

* Threefish, Skein, Skein-MAC + HMAC-Skein in 256, 512, 1024 bit block sizes.
* JCE registrations for all of these algos with standard output sizes (for digest + MAC).


### Not Accepted

#### [Align behaviour of CTR and SIC modes in the JCE API](https://github.com/timw/bc-java/commit/37b958a391b9a47b5fb70c456312dcd4c2f72667) (July 4 2013)

[pull request](https://github.com/bcgit/bc-java/pull/19)

* CTR and SIC are implemented with the same underlying engine, so make their behaviour in the JCE API consistent (previously SIC would fail on 64 bit block ciphers, while CTR would not).


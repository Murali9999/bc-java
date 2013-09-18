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

### [JCE AAD API support](https://github.com/timw/bc-java/commits/feature/aad-api) (July 03 2013)

[pull request](https://github.com/bcgit/bc-java/pull/31)

* Add Java 7 JCE AAD support to BouncyCastle JCE provider (`Cipher.updateAAD()` and `GCMParameterSpec`).
* Residual of previous contribution (in CVS days) to add online/incremental AAD processing to `AEADBlockCipher`.

### In Progress


### Accepted



### Experimental Stuff

#### [Simon and Speck Ciphers](https://github.com/timw/bc-java/commits/feature/simon-speck) (24 July 2013)
  
* Implementation of the [Simon and Speck families of lightweight block ciphers](http://eprint.iacr.org/2013/404).
* All block/key size variants are implemented, with JCE registrations and tests against published test vectors.

Speck in 32/64 bit word variants performs well in Java, although slower than Threefish due to the smaller block sizes.
Community cryptanalysis of Simon/Speck is at a very early stage, so not proposing this for BC at present.

package org.bouncycastle.crypto.a;

import org.bouncycastle.crypto.BlockCipher;

public class NewCBCBlockCipher
    // BlockCipher for historical compatibility
    implements BlockCipher, NewBlockCipherMode
{
    // Same as old CBC cipher, but with buffering to avoid copying ciphertext on long runs
}

package org.bouncycastle.crypto.a;

import org.bouncycastle.crypto.BlockCipher;


public interface NewBlockCipherMode
    extends NewCipher
{

    public BlockCipher getUnderlyingCipher();

}

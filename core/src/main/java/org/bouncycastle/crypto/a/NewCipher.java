package org.bouncycastle.crypto.a;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.InvalidCipherTextException;

public interface NewCipher
{
    public void init(boolean forEncryption, CipherParameters params)
        throws IllegalArgumentException;

    public String getAlgorithmName();

    public int getUpdateOutputSize(int len);

    public int getOutputSize(int len);

    public int processByte(byte in, byte[] out, int outOff)
        throws DataLengthException;

    // TODO: This breaks binary compatibility for StreamCipher (changes return type)
    public int processBytes(byte[] in, int inOff, int len, byte[] out, int outOff)
        throws DataLengthException;

    public int doFinal(byte[] out, int outOff)
        throws IllegalStateException,
        InvalidCipherTextException;

    public void reset();

}

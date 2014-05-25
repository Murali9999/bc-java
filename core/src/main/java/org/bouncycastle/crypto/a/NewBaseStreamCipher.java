package org.bouncycastle.crypto.a;

import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.InvalidCipherTextException;

public abstract class NewBaseStreamCipher
    implements NewStreamCipher
{
    private final byte[] singleByte = new byte[1];

    public int processByte(byte in, byte[] out, int outOff)
        throws DataLengthException
    {
        singleByte[0] = in;
        return processBytes(singleByte, 0, 1, out, outOff);
    }

    public int getUpdateOutputSize(int len)
    {
        return len;
    }

    public int getOutputSize(int len)
    {
        return len;
    }

    public int doFinal(byte[] out, int outOff)
        throws IllegalStateException,
        InvalidCipherTextException
    {
        return 0;
    }
}

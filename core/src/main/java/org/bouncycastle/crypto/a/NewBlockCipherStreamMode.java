package org.bouncycastle.crypto.a;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.OutputLengthException;

/**
 * Base class of ciphers that use a BlockCipher to generate a keystream that is xored with
 * plaintext.
 */
public abstract class NewBlockCipherStreamMode
    extends NewBaseStreamCipher
    implements NewBlockCipherMode
{
    protected final BlockCipher cipher;
    private final byte[] keyBlock;
    private int keyOffset;

    protected NewBlockCipherStreamMode(BlockCipher cipher)
    {
        this.cipher = cipher;
        this.keyBlock = new byte[cipher.getBlockSize()];
        keyOffset = keyBlock.length;
    }

    public BlockCipher getUnderlyingCipher()
    {
        return cipher;
    }

    public int getOutputSize(int len)
    {
        return len;
    }

    public int processBytes(byte[] in, int inOff, int len, byte[] out, int outOff)
        throws DataLengthException
    {
        if ((inOff + len) > in.length)
        {
            throw new DataLengthException("Input length exceeded");
        }
        if ((outOff + len) > out.length)
        {
            throw new OutputLengthException("Output buffer too small");
        }

        // TODO: Could split this to optimise aligned case
        int f = 0;
        for (int i = 0; i < len; i++)
        {
            if (keyOffset == keyBlock.length)
            {
                // Feedback in-progress data
                feedback(in, inOff + i - f, f, out, outOff + i - f);
                f = 0;
                generateNextKeyBlock(keyBlock);
                keyOffset = 0;
            }
            f++;
            out[outOff + i] = (byte)(keyBlock[keyOffset++] ^ in[inOff + i]);
        }

        // Last feedback
        feedback(in, inOff + len - f, f, out, outOff + len - f);
        return 0;
    }

    protected void feedback(byte[] in, int inOff, int len, byte[] out, int outOff)
    {
    }

    protected abstract void generateNextKeyBlock(byte[] keyBlock);

    public void reset()
    {
        cipher.reset();
        keyOffset = keyBlock.length;
    }
}

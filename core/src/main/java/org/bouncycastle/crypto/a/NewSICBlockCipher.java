package org.bouncycastle.crypto.a;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.params.ParametersWithIV;

/**
 * Implements the Segmented Integer Counter (SIC) mode on top of a simple block cipher. This mode is
 * also known as CTR mode.
 */
public class NewSICBlockCipher
    extends NewBlockCipherStreamMode
    implements BlockCipher
{
    private final byte[] counter;
    private final byte[] IV;

    /**
     * Basic constructor.
     *
     * @param c the block cipher to be used.
     */
    public NewSICBlockCipher(BlockCipher c)
    {
        super(c);
        this.counter = new byte[c.getBlockSize()];
        this.IV = new byte[c.getBlockSize()];
    }

    public void init(boolean forEncryption, // ignored by this CTR mode
                     CipherParameters params)
        throws IllegalArgumentException
    {
        if (params instanceof ParametersWithIV)
        {
            ParametersWithIV ivParam = (ParametersWithIV)params;
            byte[] iv = ivParam.getIV();
            System.arraycopy(iv, 0, IV, 0, IV.length);

            reset();

            // if null it's an IV changed only.
            if (ivParam.getParameters() != null)
            {
                cipher.init(true, ivParam.getParameters());
            }
        }
        else
        {
            throw new IllegalArgumentException("SIC mode requires ParametersWithIV");
        }
    }

    public String getAlgorithmName()
    {
        return cipher.getAlgorithmName() + "/SIC";
    }

    public int getBlockSize()
    {
        return cipher.getBlockSize();
    }

    protected void generateNextKeyBlock(byte[] keyBlock)
    {
        cipher.processBlock(counter, 0, keyBlock, 0);

        // increment counter by 1.
        for (int i = counter.length - 1; i >= 0 && ++counter[i] == 0; i--)
        {
            ; // do nothing - pre-increment and test for 0 in counter does the job.
        }
    }

    public int processBlock(byte[] in, int inOff, byte[] out, int outOff)
        throws DataLengthException,
        IllegalStateException
    {
        return processBytes(in, inOff, cipher.getBlockSize(), out, outOff);
    }

    public void reset()
    {
        super.reset();
        System.arraycopy(IV, 0, counter, 0, counter.length);
    }
}

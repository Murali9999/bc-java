package org.bouncycastle.crypto.a;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.util.encoders.Hex;

/**
 * implements a Cipher-FeedBack (CFB) mode on top of a simple cipher.
 */
public class NewCFBBlockCipher
    extends NewBlockCipherStreamMode
    implements BlockCipher
{
    private final byte[] IV;
    private final byte[] cfbV;

    private final int blockSize;
    private boolean encrypting;
    private final byte[] feedback;
    private int currentFeedback = 0;

    /**
     * Basic constructor.
     *
     * @param cipher the block cipher to be used as the basis of the feedback mode.
     * @param bitBlockSize the block size in bits (note: a multiple of 8)
     */
    public NewCFBBlockCipher(BlockCipher cipher, int bitBlockSize)
    {
        super(cipher);
        this.blockSize = bitBlockSize / 8;

        this.IV = new byte[cipher.getBlockSize()];
        this.cfbV = new byte[cipher.getBlockSize()];
        feedback = new byte[blockSize];
    }

    /**
     * Initialise the cipher and, possibly, the initialisation vector (IV). If an IV isn't passed as
     * part of the parameter, the IV will be all zeros. An IV which is too short is handled in FIPS
     * compliant fashion.
     *
     * @param encrypting if true the cipher is initialised for encryption, if false for decryption.
     * @param params the key and other data required by the cipher.
     * @exception IllegalArgumentException if the params argument is inappropriate.
     */
    public void init(boolean encrypting, CipherParameters params)
        throws IllegalArgumentException
    {
        this.encrypting = encrypting;

        if (params instanceof ParametersWithIV)
        {
            ParametersWithIV ivParam = (ParametersWithIV)params;
            byte[] iv = ivParam.getIV();

            if (iv.length < IV.length)
            {
                // prepend the supplied IV with zeros (per FIPS PUB 81)
                System.arraycopy(iv, 0, IV, IV.length - iv.length, iv.length);
                for (int i = 0; i < IV.length - iv.length; i++)
                {
                    IV[i] = 0;
                }
            }
            else
            {
                System.arraycopy(iv, 0, IV, 0, IV.length);
            }

            reset();

            // if null it's an IV changed only.
            if (ivParam.getParameters() != null)
            {
                cipher.init(true, ivParam.getParameters());
            }
        }
        else
        {
            reset();

            // if it's null, key is to be reused.
            if (params != null)
            {
                cipher.init(true, params);
            }
        }
    }

    /**
     * return the algorithm name and mode.
     *
     * @return the name of the underlying algorithm followed by "/CFB" and the block size in bits.
     */
    public String getAlgorithmName()
    {
        return cipher.getAlgorithmName() + "/CFB" + (blockSize * 8);
    }

    /**
     * return the block size we are operating at.
     *
     * @return the block size we are operating at (in bytes).
     */
    public int getBlockSize()
    {
        return blockSize;
    }

    protected void generateNextKeyBlock(byte[] keyBlock)
    {
        cipher.processBlock(cfbV, 0, keyBlock, 0);
        currentFeedback = 0;
    }

    protected void feedback(byte[] in, int inOff, int len, byte[] out, int outOff)
    {
        int newFeedback = Math.min(len, blockSize - currentFeedback);
        if (newFeedback <= 0)
        {
            return;
        }
        if (encrypting)
        {
            System.arraycopy(out, outOff, feedback, currentFeedback, newFeedback);
            System.out.println("Feeding back: " + new String(Hex.encode(feedback, 0, currentFeedback + newFeedback)));
        }
        else
        {
            System.arraycopy(in, inOff, feedback, currentFeedback, newFeedback);
        }
        currentFeedback += newFeedback;
        if (currentFeedback == blockSize)
        {
            // Shift feedback into the input block.
            System.out.println("Before: " + new String(Hex.encode(cfbV)));
            System.out.println("Feedback: " + new String(Hex.encode(feedback)));
            System.arraycopy(cfbV, blockSize, cfbV, 0, cfbV.length - blockSize);
            System.arraycopy(feedback, 0, cfbV, cfbV.length - blockSize, blockSize);
            System.out.println("After: " + new String(Hex.encode(cfbV)));
        }
    }

    /**
     * Process one block of input from the array in and write it to the out array.
     *
     * @param in the array containing the input data.
     * @param inOff offset into the in array the data starts at.
     * @param out the array the output data will be copied into.
     * @param outOff the offset into the out array the output will start at.
     * @exception DataLengthException if there isn't enough data in in, or space in out.
     * @exception IllegalStateException if the cipher isn't initialised.
     * @return the number of bytes processed and produced.
     */
    public int processBlock(byte[] in, int inOff, byte[] out, int outOff)
        throws DataLengthException,
        IllegalStateException
    {
        return processBytes(in, inOff, getBlockSize(), out, outOff);
    }

    /**
     * reset the chaining vector back to the IV and reset the underlying cipher.
     */
    public void reset()
    {
        super.reset();
        System.arraycopy(IV, 0, cfbV, 0, IV.length);
        currentFeedback = 0;
    }
}

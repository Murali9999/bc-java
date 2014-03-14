package org.bouncycastle.crypto.macs;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.Mac;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.util.Pack;

/**
 * Implementation of SipHash as specified in "SipHash: a fast short-input PRF", by Jean-Philippe
 * Aumasson and Daniel J. Bernstein (https://131002.net/siphash/siphash.pdf).
 * <p/>
 * "SipHash is a family of PRFs SipHash-c-d where the integer parameters c and d are the number of
 * compression rounds and the number of finalization rounds. A compression round is identical to a
 * finalization round and this round function is called SipRound. Given a 128-bit key k and a
 * (possibly empty) byte string m, SipHash-c-d returns a 64-bit value..."
 */
public class SipHash
    implements Mac
{
    protected final int c, d;

    protected long k0, k1;
    protected long v0, v1, v2, v3, v4;

    protected BufferedLong m = new SipHashBufferedLong();
    protected int wordCount = 0;

    /**
     * SipHash-2-4
     */
    public SipHash()
    {
        // use of 'this' confuses the flow analyser on earlier JDKs.
        this.c = 2;
        this.d = 4;
    }

    /**
     * SipHash-c-d
     *
     * @param c the number of compression rounds
     * @param d the number of finalization rounds
     */
    public SipHash(int c, int d)
    {
        this.c = c;
        this.d = d;
    }

    public String getAlgorithmName()
    {
        return "SipHash-" + c + "-" + d;
    }

    public int getMacSize()
    {
        return 8;
    }

    public void init(CipherParameters params)
        throws IllegalArgumentException
    {
        if (!(params instanceof KeyParameter))
        {
            throw new IllegalArgumentException("'params' must be an instance of KeyParameter");
        }
        KeyParameter keyParameter = (KeyParameter)params;
        byte[] key = keyParameter.getKey();
        if (key.length != 16)
        {
            throw new IllegalArgumentException("'params' must be a 128-bit key");
        }

        this.k0 = Pack.littleEndianToLong(key, 0);
        this.k1 = Pack.littleEndianToLong(key, 8);

        reset();
    }

    public static abstract class BufferedLong
    {
        public long val;
        protected int wordPos = 0;

        public void update(byte input)
        {
            long m = this.val;
            // System.err.println(1 + " in");
            m >>>= 8;
            m |= (input & 0xffL) << 56;

            if (++wordPos == 8)
            {
                processWord(val);
                wordPos = 0;
            }

        }

        public void update(byte[] input, int offset, int length)
        {
            int i = 0;
            long m = this.val;
            i = offset;
            if (wordPos != 0)
            {
                int rem = Math.min(length, 8 - wordPos);
                wordPos += rem;
                rem += offset;
                for (; i < rem; ++i)
                {
                    m >>>= 8;
                    m |= (input[i] & 0xffL) << 56;
                }
                if (wordPos == 8)
                {
                    processWord(m);
                    wordPos = 0;
                }
            }
            if (wordPos == 0)
            {
                int end = length + offset;
                int fullWords = ((end - i) & ~7) + offset;
                for (; i < fullWords; i += 8)
                {
                    m = Pack.littleEndianToLong(input, i);
                    processWord(m);
                }
                wordPos = end - i;
                for (; i < end; ++i)
                {
                    m >>>= 8;
                    m |= (input[i] & 0xffL) << 56;
                }
            }
            this.val = m;
        }

        protected abstract void processWord(long m);
    }

    public class SipHashBufferedLong
        extends BufferedLong
    {

        protected void processWord(long m)
        {
            processMessageWord(m);
        }

    }

    public void update(byte input)
        throws IllegalStateException
    {
        m.update(input);
    }

    public void update(byte[] input, int offset, int length)
        throws DataLengthException,
        IllegalStateException
    {
        // System.err.println(length + " in");
        this.m.update(input, offset, length);
    }

    public long doFinal()
        throws DataLengthException, IllegalStateException
    {
        long m = this.m.val;
        m >>>= ((8 - this.m.wordPos) << 3);
        m |= (((wordCount << 3) + this.m.wordPos) & 0xffL) << 56;

        processMessageWord(m);

        this.m.val = m;

        v2 ^= 0xffL;

        applySipRounds(d);

        long result = v0 ^ v1 ^ v2 ^ v3;

        reset();

        return result;
    }

    public int doFinal(byte[] out, int outOff)
        throws DataLengthException, IllegalStateException
    {
        long result = doFinal();
        Pack.longToLittleEndian(result, out, outOff);
        return 8;
    }

    public void reset()
    {
        v0 = k0 ^ 0x736f6d6570736575L;
        v1 = k1 ^ 0x646f72616e646f6dL;
        v2 = k0 ^ 0x6c7967656e657261L;
        v3 = k1 ^ 0x7465646279746573L;

        m.val = 0;
        m.wordPos = 0;
        wordCount = 0;
    }

    protected void processMessageWord(long m)
    {
        // System.err.println("> " + Long.toHexString(m));
        ++wordCount;
        v3 ^= m;
        applySipRounds(c);
        v0 ^= m;
    }

    protected void applySipRounds(int n)
    {
        long v0 = this.v0;
        long v1 = this.v1;
        long v2 = this.v2;
        long v3 = this.v3;

        for (int r = 0; r < n; ++r)
        {
            v0 += v1;
            v2 += v3;
            v1 = rotateLeft(v1, 13);
            v3 = rotateLeft(v3, 16);
            v1 ^= v0;
            v3 ^= v2;
            v0 = rotateLeft(v0, 32);
            v2 += v1;
            v0 += v3;
            v1 = rotateLeft(v1, 17);
            v3 = rotateLeft(v3, 21);
            v1 ^= v2;
            v3 ^= v0;
            v2 = rotateLeft(v2, 32);
        }
        this.v0 = v0;
        this.v1 = v1;
        this.v2 = v2;
        this.v3 = v3;
    }

    protected static long rotateLeft(long x, int n)
    {
        return (x << n) | (x >>> (64 - n));
    }
}

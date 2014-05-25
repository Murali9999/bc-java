package org.bouncycastle.crypto.a;


public interface NewAEADCipher
    extends NewCipher
{
    /**
     * Add a single byte to the associated data check. <br>
     * If the implementation supports it, this will be an online operation and will not retain the
     * associated data.
     * 
     * @param in the byte to be processed.
     */
    public void processAADByte(byte in);

    /**
     * Add a sequence of bytes to the associated data check. <br>
     * If the implementation supports it, this will be an online operation and will not retain the
     * associated data.
     * 
     * @param in the input byte array.
     * @param inOff the offset into the in array where the data to be processed starts.
     * @param len the number of bytes to be processed.
     */
    public void processAADBytes(byte[] in, int inOff, int len);

}

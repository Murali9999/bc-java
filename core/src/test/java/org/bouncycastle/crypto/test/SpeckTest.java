package org.bouncycastle.crypto.test;

import org.bouncycastle.crypto.engines.SpeckEngine;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTest;
import org.bouncycastle.util.test.TestResult;

public class SpeckTest
    extends SimpleTest
{
    // Test vectors from "The Simon and Speck Families of Lightweight Block Ciphers" Appendix C

    private static class Speck128Test
        extends CipherTest
    {
        static SimpleTest[] tests = {
                new BlockCipherVectorTest(0, new SpeckEngine(SpeckEngine.SPECK_128), new KeyParameter(
                        Hex.decode("0f0e0d0c0b0a0908 0706050403020100")), // k1, k0
                        "6c61766975716520 7469206564616d20",              // (x, y == pt[1],pt[0])
                        "a65d985179783265 7860fedf5c570d18"),              // (x, y == ct[1],ct[0])
                new BlockCipherVectorTest(1, new SpeckEngine(SpeckEngine.SPECK_128), new KeyParameter(
                        Hex.decode("1716151413121110 0f0e0d0c0b0a0908 0706050403020100")),
                        "7261482066656968 43206f7420746e65", "1be4cf3a13135566 f9bc185de03c1886"),
                new BlockCipherVectorTest(2, new SpeckEngine(SpeckEngine.SPECK_128), new KeyParameter(
                        Hex.decode("1f1e1d1c1b1a1918 1716151413121110 0f0e0d0c0b0a0908 0706050403020100")),
                        "65736f6874206e49 202e72656e6f6f70", "4109010405c0f53e 4eeeb48d9c188f43")};

        Speck128Test()
        {
            super(tests, new SpeckEngine(SpeckEngine.SPECK_128), new KeyParameter(new byte[16]));
        }

        public String getName()
        {
            return "Speck128";
        }
    }

    private static class Speck96Test
        extends CipherTest
    {
        static SimpleTest[] tests = {
                new BlockCipherVectorTest(0, new SpeckEngine(SpeckEngine.SPECK_96), new KeyParameter(
                        Hex.decode("0d0c0b0a0908 050403020100")), "65776f68202c 656761737520",
                        "9e4d09ab7178 62bdde8f79aa"),
                new BlockCipherVectorTest(1, new SpeckEngine(SpeckEngine.SPECK_96), new KeyParameter(
                        Hex.decode("151413121110 0d0c0b0a0908 050403020100")), "656d6974206e 69202c726576",
                        "2bf31072228a 7ae440252ee6")};

        Speck96Test()
        {
            super(tests, new SpeckEngine(SpeckEngine.SPECK_96), new KeyParameter(new byte[12]));
        }

        public String getName()
        {
            return "Speck96";
        }
    }

    private static class Speck64Test
        extends CipherTest
    {
        static SimpleTest[] tests = {
                new BlockCipherVectorTest(0, new SpeckEngine(SpeckEngine.SPECK_64), new KeyParameter(
                        Hex.decode("13121110 0b0a0908 03020100")), "74614620 736e6165", "9f7952ec 4175946c"),
                new BlockCipherVectorTest(1, new SpeckEngine(SpeckEngine.SPECK_64), new KeyParameter(
                        Hex.decode("1b1a1918 13121110 0b0a0908 03020100")), "3b726574 7475432d", "8c6fa548 454e028b")};

        Speck64Test()
        {
            super(tests, new SpeckEngine(SpeckEngine.SPECK_64), new KeyParameter(new byte[12]));
        }

        public String getName()
        {
            return "Speck64";
        }
    }

    private static class Speck48Test
        extends CipherTest
    {
        static SimpleTest[] tests = {
                new BlockCipherVectorTest(0, new SpeckEngine(SpeckEngine.SPECK_48), new KeyParameter(
                        Hex.decode("121110 0a0908 020100")), "20796c 6c6172", "c049a5 385adc"),
                new BlockCipherVectorTest(1, new SpeckEngine(SpeckEngine.SPECK_48), new KeyParameter(
                        Hex.decode("1a1918 121110 0a0908 020100")), "6d2073 696874", "735e10 b6445d")};

        Speck48Test()
        {
            super(tests, new SpeckEngine(SpeckEngine.SPECK_48), new KeyParameter(new byte[9]));
        }

        public String getName()
        {
            return "Speck48";
        }
    }

    private static class Speck32Test
        extends CipherTest
    {
        static SimpleTest[] tests = {new BlockCipherVectorTest(0, new SpeckEngine(SpeckEngine.SPECK_32),
                new KeyParameter(Hex.decode("1918 1110 0908 0100")), "6574 694c", "a868 42f2")};

        Speck32Test()
        {
            super(tests, new SpeckEngine(SpeckEngine.SPECK_32), new KeyParameter(new byte[8]));
        }

        public String getName()
        {
            return "Speck32";
        }
    }

    public static void main(String[] args)
    {
        runTest(new SpeckTest());
    }

    @Override
    public String getName()
    {
        return "SpeckTest";
    }

    @Override
    public void performTest()
        throws Exception
    {
        CipherTest[] tests = new CipherTest[]{
                new Speck128Test(),
                new Speck96Test(),
                new Speck64Test(),
                new Speck48Test(),
                new Speck32Test()};

        for (int i = 0; i < tests.length; i++)
        {
            TestResult result = tests[i].perform();
            if (!result.isSuccessful())
            {
                fail(result.toString());
            }
        }
    }
}

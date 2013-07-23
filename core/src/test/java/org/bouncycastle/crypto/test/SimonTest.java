package org.bouncycastle.crypto.test;

import org.bouncycastle.crypto.engines.SimonEngine;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTest;
import org.bouncycastle.util.test.TestResult;

public class SimonTest
    extends SimpleTest
{
    // Test vectors from "The Simon and Speck Families of Lightweight Block Ciphers" Appendix B

    private static class Simon128Test
        extends CipherTest
    {
        static SimpleTest[] tests = {
                new BlockCipherVectorTest(0, new SimonEngine(SimonEngine.SIMON_128), new KeyParameter(
                        Hex.decode("0f0e0d0c0b0a0908 0706050403020100")), // k1, k0
                        "6373656420737265 6c6c657661727420",              // (x, y == pt[1],pt[0])
                        "49681b1e1e54fe3f 65aa832af84e0bbc"),              // (x, y == ct[1],ct[0])
                new BlockCipherVectorTest(1, new SimonEngine(SimonEngine.SIMON_128), new KeyParameter(
                        Hex.decode("1716151413121110 0f0e0d0c0b0a0908 0706050403020100")),
                        "206572656874206e 6568772065626972", "c4ac61effcdc0d4f 6c9c8d6e2597b85b"),
                new BlockCipherVectorTest(2, new SimonEngine(SimonEngine.SIMON_128), new KeyParameter(
                        Hex.decode("1f1e1d1c1b1a1918 1716151413121110 0f0e0d0c0b0a0908 0706050403020100")),
                        "74206e69206d6f6f 6d69732061207369", "8d2b5579afc8a3a0 3bf72a87efe7b868")};

        Simon128Test()
        {
            super(tests, new SimonEngine(SimonEngine.SIMON_128), new KeyParameter(new byte[16]));
        }

        public String getName()
        {
            return "Simon128";
        }
    }

    private static class Simon96Test
        extends CipherTest
    {
        static SimpleTest[] tests = {
                new BlockCipherVectorTest(0, new SimonEngine(SimonEngine.SIMON_96), new KeyParameter(
                        Hex.decode("0d0c0b0a0908 050403020100")), "2072616c6c69 702065687420",
                        "602807a462b4 69063d8ff082"),
                new BlockCipherVectorTest(1, new SimonEngine(SimonEngine.SIMON_96), new KeyParameter(
                        Hex.decode("151413121110 0d0c0b0a0908 050403020100")), "746168742074 73756420666f",
                        "ecad1c6c451e 3f59c5db1ae9")};

        Simon96Test()
        {
            super(tests, new SimonEngine(SimonEngine.SIMON_96), new KeyParameter(new byte[12]));
        }

        public String getName()
        {
            return "Simon96";
        }
    }

    private static class Simon64Test
        extends CipherTest
    {
        static SimpleTest[] tests = {
                new BlockCipherVectorTest(0, new SimonEngine(SimonEngine.SIMON_64), new KeyParameter(
                        Hex.decode("13121110 0b0a0908 03020100")), "6f722067 6e696c63", "5ca2e27f 111a8fc8"),
                new BlockCipherVectorTest(1, new SimonEngine(SimonEngine.SIMON_64), new KeyParameter(
                        Hex.decode("1b1a1918 13121110 0b0a0908 03020100")), "656b696c 20646e75", "44c8fc20 b9dfa07a")};

        Simon64Test()
        {
            super(tests, new SimonEngine(SimonEngine.SIMON_64), new KeyParameter(new byte[12]));
        }

        public String getName()
        {
            return "Simon64";
        }
    }

    private static class Simon48Test
        extends CipherTest
    {
        static SimpleTest[] tests = {
                new BlockCipherVectorTest(0, new SimonEngine(SimonEngine.SIMON_48), new KeyParameter(
                        Hex.decode("121110 0a0908 020100")), "612067 6e696c", "dae5ac 292cac"),
                new BlockCipherVectorTest(1, new SimonEngine(SimonEngine.SIMON_48), new KeyParameter(
                        Hex.decode("1a1918 121110 0a0908 020100")), "726963 20646e", "6e06a5 acf156")};

        Simon48Test()
        {
            super(tests, new SimonEngine(SimonEngine.SIMON_48), new KeyParameter(new byte[9]));
        }

        public String getName()
        {
            return "Simon48";
        }
    }

    private static class Simon32Test
        extends CipherTest
    {
        static SimpleTest[] tests = {new BlockCipherVectorTest(0, new SimonEngine(SimonEngine.SIMON_32),
                new KeyParameter(Hex.decode("1918 1110 0908 0100")), "6565 6877", "c69b e9bb")};

        Simon32Test()
        {
            super(tests, new SimonEngine(SimonEngine.SIMON_32), new KeyParameter(new byte[8]));
        }

        public String getName()
        {
            return "Simon32";
        }
    }

    public static void main(String[] args)
    {
        runTest(new SimonTest());
    }

    @Override
    public String getName()
    {
        return "SimonTest";
    }

    @Override
    public void performTest()
        throws Exception
    {
        CipherTest[] tests = new CipherTest[]{
                new Simon128Test(),
                new Simon96Test(),
                new Simon64Test(),
                new Simon48Test(),
                new Simon32Test()};

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

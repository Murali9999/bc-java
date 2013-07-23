package org.bouncycastle.jcajce.provider.symmetric;

import org.bouncycastle.crypto.CipherKeyGenerator;
import org.bouncycastle.crypto.engines.SimonEngine;
import org.bouncycastle.crypto.macs.GMac;
import org.bouncycastle.crypto.modes.GCMBlockCipher;
import org.bouncycastle.jcajce.provider.config.ConfigurableProvider;
import org.bouncycastle.jcajce.provider.symmetric.util.BaseBlockCipher;
import org.bouncycastle.jcajce.provider.symmetric.util.BaseKeyGenerator;
import org.bouncycastle.jcajce.provider.symmetric.util.BaseMac;
import org.bouncycastle.jcajce.provider.symmetric.util.IvAlgorithmParameters;

public final class Simon
{

    private Simon()
    {
    }

    public static class ECB_128
        extends BaseBlockCipher
    {
        public ECB_128()
        {
            super(new SimonEngine(SimonEngine.SIMON_128));
        }
    }

    public static class ECB_96
        extends BaseBlockCipher
    {
        public ECB_96()
        {
            super(new SimonEngine(SimonEngine.SIMON_96));
        }
    }

    public static class ECB_64
        extends BaseBlockCipher
    {
        public ECB_64()
        {
            super(new SimonEngine(SimonEngine.SIMON_64));
        }
    }

    public static class ECB_48
        extends BaseBlockCipher
    {
        public ECB_48()
        {
            super(new SimonEngine(SimonEngine.SIMON_48));
        }
    }

    public static class ECB_32
        extends BaseBlockCipher
    {
        public ECB_32()
        {
            super(new SimonEngine(SimonEngine.SIMON_32));
        }
    }

    public static class KeyGen_128
        extends BaseKeyGenerator
    {
        public KeyGen_128()
        {
            super("Simon128", 128, new CipherKeyGenerator());
        }
    }

    public static class KeyGen_96
        extends BaseKeyGenerator
    {
        public KeyGen_96()
        {
            super("Simon96", 96, new CipherKeyGenerator());
        }
    }

    public static class KeyGen_64
        extends BaseKeyGenerator
    {
        public KeyGen_64()
        {
            super("Simon64", 96, new CipherKeyGenerator());
        }
    }

    public static class KeyGen_48
        extends BaseKeyGenerator
    {
        public KeyGen_48()
        {
            super("Simon48", 72, new CipherKeyGenerator());
        }
    }

    public static class KeyGen_32
        extends BaseKeyGenerator
    {
        public KeyGen_32()
        {
            super("Simon32", 64, new CipherKeyGenerator());
        }
    }

    public static class AlgParams_128
        extends IvAlgorithmParameters
    {
        protected String engineToString()
        {
            return "Simon128 IV";
        }
    }

    public static class AlgParams_96
        extends IvAlgorithmParameters
    {
        protected String engineToString()
        {
            return "Simon96 IV";
        }
    }

    public static class AlgParams_64
        extends IvAlgorithmParameters
    {
        protected String engineToString()
        {
            return "Simon64 IV";
        }
    }

    public static class AlgParams_48
        extends IvAlgorithmParameters
    {
        protected String engineToString()
        {
            return "Simon48 IV";
        }
    }

    public static class AlgParams_32
        extends IvAlgorithmParameters
    {
        protected String engineToString()
        {
            return "Simon32 IV";
        }
    }

    public static class SpecGMAC
        extends BaseMac
    {
        public SpecGMAC()
        {
            super(new GMac(new GCMBlockCipher(new SimonEngine(SimonEngine.SIMON_128))));
        }
    }

    public static class Mappings
        extends SymmetricAlgorithmProvider
    {
        private static final String PREFIX = Simon.class.getName();

        public Mappings()
        {
        }

        public void configure(ConfigurableProvider provider)
        {
            provider.addAlgorithm("Cipher.Simon128", PREFIX + "$ECB_128");
            provider.addAlgorithm("Cipher.Simon96", PREFIX + "$ECB_96");
            provider.addAlgorithm("Cipher.Simon64", PREFIX + "$ECB_64");
            provider.addAlgorithm("Cipher.Simon48", PREFIX + "$ECB_48");
            provider.addAlgorithm("Cipher.Simon32", PREFIX + "$ECB_32");

            provider.addAlgorithm("KeyGenerator.Simon128", PREFIX + "$KeyGen_128");
            provider.addAlgorithm("KeyGenerator.Simon96", PREFIX + "$KeyGen_96");
            provider.addAlgorithm("KeyGenerator.Simon64", PREFIX + "$KeyGen_64");
            provider.addAlgorithm("KeyGenerator.Simon48", PREFIX + "$KeyGen_48");
            provider.addAlgorithm("KeyGenerator.Simon32", PREFIX + "$KeyGen_32");

            provider.addAlgorithm("AlgorithmParameters.Simon128", PREFIX + "$AlgParams_128");
            provider.addAlgorithm("AlgorithmParameters.Simon96", PREFIX + "$AlgParams_96");
            provider.addAlgorithm("AlgorithmParameters.Simon64", PREFIX + "$AlgParams_64");
            provider.addAlgorithm("AlgorithmParameters.Simon48", PREFIX + "$AlgParams_48");
            provider.addAlgorithm("AlgorithmParameters.Simon32", PREFIX + "$AlgParams_32");

            addGMacAlgorithm(provider, "Simon128", PREFIX + "$SpecGMAC", PREFIX + "$KeyGen_128");
            // addPoly1305Algorithm(provider, "Simon128", PREFIX + "$POLY1305", PREFIX +
            // "$KeyGen_128");
            // CMAC?
        }
    }
}

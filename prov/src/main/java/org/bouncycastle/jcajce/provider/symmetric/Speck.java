package org.bouncycastle.jcajce.provider.symmetric;

import org.bouncycastle.crypto.CipherKeyGenerator;
import org.bouncycastle.crypto.engines.SpeckEngine;
import org.bouncycastle.crypto.macs.GMac;
import org.bouncycastle.crypto.modes.GCMBlockCipher;
import org.bouncycastle.jcajce.provider.config.ConfigurableProvider;
import org.bouncycastle.jcajce.provider.symmetric.util.BaseBlockCipher;
import org.bouncycastle.jcajce.provider.symmetric.util.BaseKeyGenerator;
import org.bouncycastle.jcajce.provider.symmetric.util.BaseMac;
import org.bouncycastle.jcajce.provider.symmetric.util.IvAlgorithmParameters;

public final class Speck
{

    private Speck()
    {
    }

    public static class ECB_128
        extends BaseBlockCipher
    {
        public ECB_128()
        {
            super(new SpeckEngine(SpeckEngine.SPECK_128));
        }
    }

    public static class ECB_96
        extends BaseBlockCipher
    {
        public ECB_96()
        {
            super(new SpeckEngine(SpeckEngine.SPECK_96));
        }
    }

    public static class ECB_64
        extends BaseBlockCipher
    {
        public ECB_64()
        {
            super(new SpeckEngine(SpeckEngine.SPECK_64));
        }
    }

    public static class ECB_48
        extends BaseBlockCipher
    {
        public ECB_48()
        {
            super(new SpeckEngine(SpeckEngine.SPECK_48));
        }
    }

    public static class ECB_32
        extends BaseBlockCipher
    {
        public ECB_32()
        {
            super(new SpeckEngine(SpeckEngine.SPECK_32));
        }
    }

    public static class KeyGen_128
        extends BaseKeyGenerator
    {
        public KeyGen_128()
        {
            super("Speck128", 128, new CipherKeyGenerator());
        }
    }

    public static class KeyGen_96
        extends BaseKeyGenerator
    {
        public KeyGen_96()
        {
            super("Speck96", 96, new CipherKeyGenerator());
        }
    }

    public static class KeyGen_64
        extends BaseKeyGenerator
    {
        public KeyGen_64()
        {
            super("Speck64", 96, new CipherKeyGenerator());
        }
    }

    public static class KeyGen_48
        extends BaseKeyGenerator
    {
        public KeyGen_48()
        {
            super("Speck48", 72, new CipherKeyGenerator());
        }
    }

    public static class KeyGen_32
        extends BaseKeyGenerator
    {
        public KeyGen_32()
        {
            super("Speck32", 64, new CipherKeyGenerator());
        }
    }

    public static class AlgParams_128
        extends IvAlgorithmParameters
    {
        protected String engineToString()
        {
            return "Speck128 IV";
        }
    }

    public static class AlgParams_96
        extends IvAlgorithmParameters
    {
        protected String engineToString()
        {
            return "Speck96 IV";
        }
    }

    public static class AlgParams_64
        extends IvAlgorithmParameters
    {
        protected String engineToString()
        {
            return "Speck64 IV";
        }
    }

    public static class AlgParams_48
        extends IvAlgorithmParameters
    {
        protected String engineToString()
        {
            return "Speck48 IV";
        }
    }

    public static class AlgParams_32
        extends IvAlgorithmParameters
    {
        protected String engineToString()
        {
            return "Speck32 IV";
        }
    }

    public static class SpecGMAC
        extends BaseMac
    {
        public SpecGMAC()
        {
            super(new GMac(new GCMBlockCipher(new SpeckEngine(SpeckEngine.SPECK_128))));
        }
    }

    public static class Mappings
        extends SymmetricAlgorithmProvider
    {
        private static final String PREFIX = Speck.class.getName();

        public Mappings()
        {
        }

        public void configure(ConfigurableProvider provider)
        {
            provider.addAlgorithm("Cipher.Speck128", PREFIX + "$ECB_128");
            provider.addAlgorithm("Cipher.Speck96", PREFIX + "$ECB_96");
            provider.addAlgorithm("Cipher.Speck64", PREFIX + "$ECB_64");
            provider.addAlgorithm("Cipher.Speck48", PREFIX + "$ECB_48");
            provider.addAlgorithm("Cipher.Speck32", PREFIX + "$ECB_32");

            provider.addAlgorithm("KeyGenerator.Speck128", PREFIX + "$KeyGen_128");
            provider.addAlgorithm("KeyGenerator.Speck96", PREFIX + "$KeyGen_96");
            provider.addAlgorithm("KeyGenerator.Speck64", PREFIX + "$KeyGen_64");
            provider.addAlgorithm("KeyGenerator.Speck48", PREFIX + "$KeyGen_48");
            provider.addAlgorithm("KeyGenerator.Speck32", PREFIX + "$KeyGen_32");

            provider.addAlgorithm("AlgorithmParameters.Speck128", PREFIX + "$AlgParams_128");
            provider.addAlgorithm("AlgorithmParameters.Speck96", PREFIX + "$AlgParams_96");
            provider.addAlgorithm("AlgorithmParameters.Speck64", PREFIX + "$AlgParams_64");
            provider.addAlgorithm("AlgorithmParameters.Speck48", PREFIX + "$AlgParams_48");
            provider.addAlgorithm("AlgorithmParameters.Speck32", PREFIX + "$AlgParams_32");

            addGMacAlgorithm(provider, "Speck128", PREFIX + "$SpecGMAC", PREFIX + "$KeyGen_128");
            // addPoly1305Algorithm(provider, "Speck128", PREFIX + "$POLY1305", PREFIX +
            // "$KeyGen_128");
            // CMAC?
        }
    }
}

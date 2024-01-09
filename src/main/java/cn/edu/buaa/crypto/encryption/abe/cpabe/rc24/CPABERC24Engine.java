package cn.edu.buaa.crypto.encryption.abe.cpabe.rc24;

import cn.edu.buaa.crypto.algebra.serparams.PairingCipherSerParameter;
import cn.edu.buaa.crypto.algebra.serparams.PairingKeyEncapsulationSerPair;
import cn.edu.buaa.crypto.algebra.serparams.PairingKeySerPair;
import cn.edu.buaa.crypto.algebra.serparams.PairingKeySerParameter;
import cn.edu.buaa.crypto.encryption.abe.cpabe.CPABEEngine;
import cn.edu.buaa.crypto.encryption.abe.cpabe.genparams.CPABEDecryptionGenerationParameter;
import cn.edu.buaa.crypto.encryption.abe.cpabe.genparams.CPABEEncryptionGenerationParameter;
import cn.edu.buaa.crypto.encryption.abe.cpabe.genparams.CPABEKeyPairGenerationParameter;
import cn.edu.buaa.crypto.encryption.abe.cpabe.genparams.CPABESecretKeyGenerationParameter;
import cn.edu.buaa.crypto.encryption.abe.cpabe.rc24.generators.CPABERC24DecryptionGenerator;
import cn.edu.buaa.crypto.encryption.abe.cpabe.rc24.generators.CPABERC24EncryptionGenerator;
import cn.edu.buaa.crypto.encryption.abe.cpabe.rc24.generators.CPABERC24KeyPairGenerator;
import cn.edu.buaa.crypto.encryption.abe.cpabe.rc24.generators.CPABERC24SecretKeyGenerator;
import cn.edu.buaa.crypto.encryption.abe.cpabe.rc24.serparams.*;
import cn.edu.buaa.crypto.utils.PairingUtils;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.PairingParameters;
import org.bouncycastle.crypto.InvalidCipherTextException;

/**
 * Created by Weiran Liu on 2016/11/29.
 *
 * Rouselakis-Waters large-universe CP-ABE engine.
 */
public class CPABERC24Engine extends CPABEEngine {
    private static final String SCHEME_NAME = "RC-24 LD-ABABE";
    private static CPABERC24Engine engine;

    public static CPABERC24Engine getInstance() {
        if (engine == null) {
            engine = new CPABERC24Engine();
        }
        return engine;
    }

    private CPABERC24Engine() {
        super(SCHEME_NAME, ProveSecModel.Standard, PayloadSecLevel.CPA, PredicateSecLevel.NON_ANON);
    }

    public PairingKeySerPair setup(PairingParameters pairingParameters, int maxAttributesNum) {
        CPABERC24KeyPairGenerator keyPairGenerator = new CPABERC24KeyPairGenerator();
        keyPairGenerator.init(new CPABEKeyPairGenerationParameter(pairingParameters));

        return keyPairGenerator.generateKeyPair();
    }

    public PairingKeySerParameter keyGen(PairingKeySerParameter publicKey, PairingKeySerParameter masterKey, String[] attributes) {
        if (!(publicKey instanceof CPABERC24PublicKeySerParameter)){
            PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, publicKey, CPABERC24PublicKeySerParameter.class.getName());
        }
        if (!(masterKey instanceof CPABERC24MasterSecretKeySerParameter)) {
            PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, masterKey, CPABERC24MasterSecretKeySerParameter.class.getName());
        }
        CPABERC24SecretKeyGenerator secretKeyGenerator = new CPABERC24SecretKeyGenerator();
        secretKeyGenerator.init(new CPABESecretKeyGenerationParameter(publicKey, masterKey, attributes));
        return secretKeyGenerator.generateKey();
    }

    public PairingCipherSerParameter encryption(PairingKeySerParameter publicKey, int[][] accessPolicyIntArrays, String[] rhos, Element message) {
        if (!(publicKey instanceof CPABERC24PublicKeySerParameter)){
            PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, publicKey, CPABERC24PublicKeySerParameter.class.getName());
        }
        CPABERC24EncryptionGenerator encryptionGenerator = new CPABERC24EncryptionGenerator();
        encryptionGenerator.init(new CPABEEncryptionGenerationParameter(
                accessControlEngine, publicKey, accessPolicyIntArrays, rhos, message));
        return encryptionGenerator.generateCiphertext();
    }

    public PairingKeyEncapsulationSerPair encapsulation(PairingKeySerParameter publicKey, int[][] accessPolicyIntArrays, String[] rhos) {
        if (!(publicKey instanceof CPABERC24PublicKeySerParameter)){
            PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, publicKey, CPABERC24PublicKeySerParameter.class.getName());
        }
        CPABERC24EncryptionGenerator encryptionGenerator = new CPABERC24EncryptionGenerator();
        encryptionGenerator.init(new CPABEEncryptionGenerationParameter(
                accessControlEngine, publicKey, accessPolicyIntArrays, rhos, null));
        return encryptionGenerator.generateEncryptionPair();
    }

    public Element decryption(PairingKeySerParameter publicKey, PairingKeySerParameter secretKey,
                              int[][] accessPolicyIntArrays, String[] rhos, PairingCipherSerParameter ciphertext)
            throws InvalidCipherTextException {
        if (!(publicKey instanceof CPABERC24PublicKeySerParameter)){
            PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, publicKey, CPABERC24PublicKeySerParameter.class.getName());
        }
        if (!(secretKey instanceof CPABERC24SecretKeySerParameter)){
            PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, secretKey, CPABERC24SecretKeySerParameter.class.getName());
        }
        if (!(ciphertext instanceof CPABERC24CiphertextSerParameter)){
            PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, ciphertext, CPABERC24CiphertextSerParameter.class.getName());
        }
        CPABERC24DecryptionGenerator decryptionGenerator = new CPABERC24DecryptionGenerator();
        decryptionGenerator.init(new CPABEDecryptionGenerationParameter(
                accessControlEngine, publicKey, secretKey, accessPolicyIntArrays, rhos, ciphertext));
        return decryptionGenerator.recoverMessage();
    }

    public byte[] decapsulation(PairingKeySerParameter publicKey, PairingKeySerParameter secretKey,
                                int[][] accessPolicyIntArrays, String[] rhos, PairingCipherSerParameter header)
            throws InvalidCipherTextException {
        if (!(publicKey instanceof CPABERC24PublicKeySerParameter)){
            PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, publicKey, CPABERC24PublicKeySerParameter.class.getName());
        }
        if (!(secretKey instanceof CPABERC24SecretKeySerParameter)){
            PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, secretKey, CPABERC24SecretKeySerParameter.class.getName());
        }
        if (!(header instanceof CPABERC24HeaderSerParameter)){
            PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, header, CPABERC24HeaderSerParameter.class.getName());
        }
        CPABERC24DecryptionGenerator decryptionGenerator = new CPABERC24DecryptionGenerator();
        decryptionGenerator.init(new CPABEDecryptionGenerationParameter(
                accessControlEngine, publicKey, secretKey, accessPolicyIntArrays, rhos, header));
        return decryptionGenerator.recoverKey();
    }
}

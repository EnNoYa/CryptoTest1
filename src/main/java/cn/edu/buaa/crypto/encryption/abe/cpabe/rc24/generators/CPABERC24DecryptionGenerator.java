package cn.edu.buaa.crypto.encryption.abe.cpabe.rc24.generators;

import cn.edu.buaa.crypto.access.AccessControlEngine;
import cn.edu.buaa.crypto.access.AccessControlParameter;
import cn.edu.buaa.crypto.access.UnsatisfiedAccessControlException;
import cn.edu.buaa.crypto.algebra.generators.PairingDecapsulationGenerator;
import cn.edu.buaa.crypto.algebra.generators.PairingDecryptionGenerator;
import cn.edu.buaa.crypto.encryption.abe.cpabe.genparams.CPABEDecryptionGenerationParameter;
import cn.edu.buaa.crypto.encryption.abe.cpabe.rc24.serparams.CPABERC24CiphertextSerParameter;
import cn.edu.buaa.crypto.encryption.abe.cpabe.rc24.serparams.CPABERC24HeaderSerParameter;
import cn.edu.buaa.crypto.encryption.abe.cpabe.rc24.serparams.CPABERC24PublicKeySerParameter;
import cn.edu.buaa.crypto.encryption.abe.cpabe.rc24.serparams.CPABERC24SecretKeySerParameter;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.InvalidCipherTextException;

import java.util.Map;

/**
 * Edited by ENY 
 * 
 * Reference:
 *
 * Created by Weiran Liu on 2016/11/29.
 *
 * Rouselakis-Waters CP-ABE public key / master secret key generator.
 */
public class CPABERC24DecryptionGenerator implements PairingDecryptionGenerator, PairingDecapsulationGenerator {
    protected CPABEDecryptionGenerationParameter parameter;
    protected Element Emp;

    public void init(CipherParameters parameter) {
        this.parameter = (CPABEDecryptionGenerationParameter) parameter;
    }

    protected void computeDecapsulation() throws InvalidCipherTextException {
        CPABERC24PublicKeySerParameter publicKeyParameter = (CPABERC24PublicKeySerParameter) this.parameter.getPublicKeyParameter();
        CPABERC24SecretKeySerParameter secretKeyParameter = (CPABERC24SecretKeySerParameter) this.parameter.getSecretKeyParameter();
        CPABERC24HeaderSerParameter ciphertextParameter = (CPABERC24HeaderSerParameter) this.parameter.getCiphertextParameter();
        AccessControlEngine accessControlEngine = this.parameter.getAccessControlEngine();
        Pairing pairing = PairingFactory.getPairing(publicKeyParameter.getParameters());
        try {
            AccessControlParameter accessControlParameter
                    = accessControlEngine.generateAccessControl(this.parameter.getAccessPolicy(), this.parameter.getRhos());
            Map<String, Element> omegaElementsMap = accessControlEngine.reconstructOmegas(pairing, secretKeyParameter.getAttributes(), accessControlParameter);

            this.Emp = pairing.pairing(ciphertextParameter.getEs(), secretKeyParameter.getD2());
            Element A = pairing.getGT().newOneElement().getImmutable();
            for (String attribute : omegaElementsMap.keySet()) {
                Element E1 = ciphertextParameter.getE1At(attribute);
                Element D3 = secretKeyParameter.getD3();
                Element E2 = ciphertextParameter.getE2At(attribute);
                Element D1 = secretKeyParameter.getD1At(attribute);
                Element lambda = omegaElementsMap.get(attribute);
                A = A.mul(pairing.pairing(D3, E1).mul(pairing.pairing(D1, E2)).powZn(lambda)).getImmutable();
            }
            Emp = Emp.div(A).getImmutable();
            //one server skip mul
            Emp = Emp.powZn(secretKeyParameter.getSigma()).getImmutable();
        } catch (UnsatisfiedAccessControlException e) {
            throw new InvalidCipherTextException("Attributes associated with the ciphertext do not satisfy access policy associated with the secret key.");
        }
    }

    public Element recoverMessage() throws InvalidCipherTextException {
        computeDecapsulation();
        CPABERC24CiphertextSerParameter ciphertextParameter = (CPABERC24CiphertextSerParameter) this.parameter.getCiphertextParameter();
            return ciphertextParameter.getEm().div(Emp).getImmutable();
    }

    public byte[] recoverKey() throws InvalidCipherTextException {
        computeDecapsulation();
        return this.Emp.toBytes();
    }
}

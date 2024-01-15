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
import cn.edu.buaa.crypto.encryption.abe.cpabe.rc24.tools.CPABERC24Hash;
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
    protected Element Ev;

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
            this.Emp = this.Emp.div(A).getImmutable();
            //one server skip mul
            this.Emp = this.Emp.powZn(secretKeyParameter.getSigma()).getImmutable();
            this.Ev = CPABERC24Hash.GthashToZp(Emp,pairing);

            if(!Ev.isEqual(ciphertextParameter.getEv())){
                throw new InvalidCipherTextException("Hash of the ciphertext do not match.");
            }
        } catch (UnsatisfiedAccessControlException e) {
            throw new InvalidCipherTextException("Attributes associated with the ciphertext do not satisfy access policy associated with the secret key.");
        }
    }

    protected void userAuth() throws InvalidCipherTextException {
        CPABERC24PublicKeySerParameter publicKeyParameter = (CPABERC24PublicKeySerParameter) this.parameter.getPublicKeyParameter();
        CPABERC24SecretKeySerParameter secretKeyParameter = (CPABERC24SecretKeySerParameter) this.parameter.getSecretKeyParameter();
        CPABERC24HeaderSerParameter ciphertextParameter = (CPABERC24HeaderSerParameter) this.parameter.getCiphertextParameter();
        AccessControlEngine accessControlEngine = this.parameter.getAccessControlEngine();
        Pairing pairing = PairingFactory.getPairing(publicKeyParameter.getParameters());
        try {
            AccessControlParameter accessControlParameter
                    = accessControlEngine.generateAccessControl(this.parameter.getAccessPolicy(), this.parameter.getRhos());
            Map<String, Element> omegaElementsMap = accessControlEngine.reconstructOmegas(pairing, secretKeyParameter.getAttributes(), accessControlParameter);

            this.Emp = pairing.getGT().newOneElement().getImmutable();
            Element hashUid = CPABERC24Hash.ShashToG("UE01",pairing);
            for (String attribute : omegaElementsMap.keySet()) {
                Element E2 = ciphertextParameter.getE2At(attribute);
                Element E3 = ciphertextParameter.getE3At(attribute);              
                Element E4 = ciphertextParameter.getE4At(attribute);
                Element UAK1 = secretKeyParameter.getUAK1At(attribute);
                Element lambda = omegaElementsMap.get(attribute);
                Emp = Emp.mul(pairing.pairing(hashUid, E4).mul(E3).div(pairing.pairing(UAK1, E2)).powZn(lambda)).getImmutable();
            }

        } catch (UnsatisfiedAccessControlException e) {
            throw new InvalidCipherTextException("Attributes associated with the ciphertext do not satisfy access policy associated with the secret key.");
        }
    }
    public Element recoverMessage() throws InvalidCipherTextException {
        computeDecapsulation();
        CPABERC24CiphertextSerParameter ciphertextParameter = (CPABERC24CiphertextSerParameter) this.parameter.getCiphertextParameter();
        return ciphertextParameter.getEm().div(this.Emp).getImmutable();
    }

    public Element recoverableCheck() throws InvalidCipherTextException {
        userAuth();
        return this.Emp;
    }
    public byte[] recoverKey() throws InvalidCipherTextException {
        computeDecapsulation();
        return this.Ev.toBytes();
    }
}

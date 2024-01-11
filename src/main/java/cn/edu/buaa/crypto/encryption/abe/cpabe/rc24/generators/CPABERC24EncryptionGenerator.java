package cn.edu.buaa.crypto.encryption.abe.cpabe.rc24.generators;

import cn.edu.buaa.crypto.access.AccessControlEngine;
import cn.edu.buaa.crypto.access.AccessControlParameter;
import cn.edu.buaa.crypto.algebra.generators.PairingEncapsulationPairGenerator;
import cn.edu.buaa.crypto.algebra.generators.PairingEncryptionGenerator;
import cn.edu.buaa.crypto.algebra.serparams.PairingCipherSerParameter;
import cn.edu.buaa.crypto.algebra.serparams.PairingKeyEncapsulationSerPair;
import cn.edu.buaa.crypto.encryption.abe.cpabe.genparams.CPABEEncryptionGenerationParameter;
import cn.edu.buaa.crypto.encryption.abe.cpabe.rc24.serparams.CPABERC24CiphertextSerParameter;
import cn.edu.buaa.crypto.encryption.abe.cpabe.rc24.serparams.CPABERC24HeaderSerParameter;
import cn.edu.buaa.crypto.encryption.abe.cpabe.rc24.serparams.CPABERC24PublicKeySerParameter;
import cn.edu.buaa.crypto.encryption.abe.cpabe.rc24.tools.CPABERC24Hash;
import cn.edu.buaa.crypto.utils.PairingUtils;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import org.bouncycastle.crypto.CipherParameters;

import java.util.HashMap;
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
public class CPABERC24EncryptionGenerator implements PairingEncryptionGenerator, PairingEncapsulationPairGenerator {
    private CPABERC24PublicKeySerParameter publicKeyParameter;
    protected CPABEEncryptionGenerationParameter parameter;
    protected AccessControlParameter accessControlParameter;
    protected Element s;
    protected Element zeta;
    protected Element Es;
    protected Element Ev;
    protected Map<String, Element> E1;
    protected Map<String, Element> E2;
    protected Map<String, Element> E3;
    protected Map<String, Element> E4;
    
    public void init(CipherParameters parameter) {
        this.parameter = (CPABEEncryptionGenerationParameter) parameter;
        this.publicKeyParameter = (CPABERC24PublicKeySerParameter) this.parameter.getPublicKeyParameter();
    }

    protected void computeEncapsulation() {
        int[][] accessPolicy = this.parameter.getAccessPolicy();
        String[] rhos = this.parameter.getRhos(); //(A,p<---this)
        AccessControlEngine accessControlEngine = this.parameter.getAccessControlEngine();
        this.accessControlParameter = accessControlEngine.generateAccessControl(accessPolicy, rhos);

        Pairing pairing = PairingFactory.getPairing(publicKeyParameter.getParameters());
        this.s = pairing.getZr().newRandomElement().getImmutable();
        this.Es = publicKeyParameter.getG().powZn(s).getImmutable();

        Map<String, Element> lambdas = accessControlEngine.secretSharing(pairing, s, accessControlParameter);
        Map<String, Element> omegas = accessControlEngine.secretSharing(pairing, pairing.getZr().newZeroElement(), accessControlParameter);
        this.E1 = new HashMap<String, Element>();
        this.E2 = new HashMap<String, Element>();
        this.E3 = new HashMap<String, Element>();
        this.E4 = new HashMap<String, Element>();
        for (String rho : lambdas.keySet()) {
            // Element elementRho = PairingUtils.MapStringToGroup(pairing, rho, PairingUtils.PairingGroupType.Zr);
            this.zeta = pairing.getZr().newRandomElement().getImmutable();
            Element E1s = publicKeyParameter.getGHh().get(rho).negate().powZn(zeta).getImmutable();
            E1s = E1s.powZn(publicKeyParameter.getCt()).getImmutable();
            E1s = E1s.mul(publicKeyParameter.getG().powZn(lambdas.get(rho))).getImmutable();
            Element E3s = publicKeyParameter.getEggHb().get(rho).powZn(zeta).getImmutable();
            E3s = E3s.powZn(publicKeyParameter.getCt()).getImmutable();
            Element E4s = publicKeyParameter.getGHg().get(rho).powZn(zeta).getImmutable();
            E4s = E4s.powZn(publicKeyParameter.getCt()).getImmutable();
            E4s = E4s.mul(publicKeyParameter.getG().powZn(omegas.get(rho))).getImmutable();
            E1.put(rho, E1s);
            E2.put(rho, publicKeyParameter.getG().powZn(zeta));
            E3.put(rho, E3s);
            E4.put(rho, E4s);
        }
    }

    public PairingCipherSerParameter generateCiphertext() {
        computeEncapsulation();

        Pairing pairing = PairingFactory.getPairing(publicKeyParameter.getParameters());
        Element Em = publicKeyParameter.getEggAlpha().powZn(s).mul(this.parameter.getMessage()).getImmutable();
        Ev = CPABERC24Hash.GthashToZp(Em,pairing);
        return new CPABERC24CiphertextSerParameter(publicKeyParameter.getParameters(), Em, Ev, Es, E1, E2, E3, E4);
    }
    // ?
    public PairingKeyEncapsulationSerPair generateEncryptionPair() {
        computeEncapsulation();
        return new PairingKeyEncapsulationSerPair(
                this.Ev.toBytes(),
                new CPABERC24HeaderSerParameter(publicKeyParameter.getParameters(), Ev, Es, E1, E2, E3, E4)
        );
    }
}
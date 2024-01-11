package cn.edu.buaa.crypto.encryption.abe.cpabe.rc24.generators;

import cn.edu.buaa.crypto.algebra.generators.PairingKeyPairGenerator;
import cn.edu.buaa.crypto.algebra.serparams.PairingKeySerPair;
import cn.edu.buaa.crypto.encryption.abe.cpabe.genparams.CPABEKeyPairGenerationParameter;
import cn.edu.buaa.crypto.encryption.abe.cpabe.genparams.CPABESecretKeyGenerationParameter;
import cn.edu.buaa.crypto.encryption.abe.cpabe.rc24.serparams.CPABERC24MasterSecretKeySerParameter;
import cn.edu.buaa.crypto.encryption.abe.cpabe.rc24.serparams.CPABERC24PublicKeySerParameter;
import cn.edu.buaa.crypto.encryption.abe.cpabe.rc24.tools.CPABERC24Hash;
import cn.edu.buaa.crypto.utils.PairingUtils;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.crypto.KeyGenerationParameters;

/**
 * Edited by ENY 
 * 
 * Reference:
 *
 * Created by Weiran Liu on 2016/11/29.
 *
 * Rouselakis-Waters CP-ABE public key / master secret key generator.
 */
public class CPABERC24KeyPairGenerator implements PairingKeyPairGenerator {
    protected CPABEKeyPairGenerationParameter parameters;
    // CASetup 
    public void init(KeyGenerationParameters keyGenerationParameter) {
        this.parameters = (CPABEKeyPairGenerationParameter) keyGenerationParameter;
    }

    public PairingKeySerPair generateKeyPair() {
        String[] attributes = this.parameters.getAttributes();
        Pairing pairing = PairingFactory.getPairing(this.parameters.getPairingParameters());

        Element alpha = pairing.getZr().newRandomElement().getImmutable();
        Element eta = pairing.getZr().newRandomElement().getImmutable();
        Element beta ;
        Element gamma ;
        Element h ;
        // only one type
        // Map<String, Element> t = new HashMap<String, Element>();
        // Map<String, Element> c_t = new HashMap<String, Element>();
        Element t = pairing.getZr().newRandomElement().getImmutable();
        Element ct = pairing.getZr().newRandomElement().getImmutable();

        Element g = pairing.getG1().newRandomElement().getImmutable();

        Element gEta = g.powZn(eta).getImmutable();      
        Element hashAID = CPABERC24Hash.ShashToZp("GN-001", pairing).powZn(t).getImmutable();   

        
        Map<String, Element> hAb = new HashMap<String, Element>();
        Map<String, Element> hAh = new HashMap<String, Element>();
        Map<String, Element> hAg = new HashMap<String, Element>();

        Element eggAlpha = pairing.pairing(g, g).powZn(alpha).getImmutable();
        Map<String, Element> eggHb = new HashMap<String, Element>();
        Map<String, Element> gHh = new HashMap<String, Element>();
        Map<String, Element> gHg = new HashMap<String, Element>();
        Element eggH = pairing.pairing(g, g).powZn(hashAID.div(ct)).getImmutable();
        Element gH = g.powZn(hashAID.div(ct)).getImmutable();

        for (String attribute : attributes) {
            beta = pairing.getZr().newRandomElement().getImmutable();
            gamma = pairing.getZr().newRandomElement().getImmutable();
            h = pairing.getZr().newRandomElement().getImmutable();

            hAb.put(attribute, hashAID.mul(beta).getImmutable());
            hAh.put(attribute, hashAID.mul(h).getImmutable());
            hAg.put(attribute, hashAID.mul(gamma).getImmutable());

            eggHb.put(attribute, pairing.pairing(g, g).powZn(hAb.get(attribute).div(ct)).getImmutable());
            gHh.put(attribute, g.powZn(hAh.get(attribute).div(ct)).getImmutable());
            gHg.put(attribute, g.powZn(hAg.get(attribute).div(ct)).getImmutable());
        }
        
        return new PairingKeySerPair(
                new CPABERC24PublicKeySerParameter(this.parameters.getPairingParameters(), g, gEta, eggAlpha, eggHb, gHh, gHg, eggH, gH, ct), //c_t not should be here
                new CPABERC24MasterSecretKeySerParameter(this.parameters.getPairingParameters(), alpha, hAb, hAh, hAg, hashAID));
    }
}
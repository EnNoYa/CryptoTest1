package cn.edu.buaa.crypto.encryption.abe.cpabe.rc24.generators;

import cn.edu.buaa.crypto.algebra.generators.PairingKeyPairGenerator;
import cn.edu.buaa.crypto.algebra.serparams.PairingKeySerPair;
import cn.edu.buaa.crypto.encryption.abe.cpabe.genparams.CPABEKeyPairGenerationParameter;
import cn.edu.buaa.crypto.encryption.abe.cpabe.rc24.serparams.CPABERC24MasterSecretKeySerParameter;
import cn.edu.buaa.crypto.encryption.abe.cpabe.rc24.serparams.CPABERC24PublicKeySerParameter;
import cn.edu.buaa.crypto.encryption.abe.cpabe.rc24.tools.CPABERC24Hash;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
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
        Pairing pairing = PairingFactory.getPairing(this.parameters.getPairingParameters());

        Element alpha = pairing.getZr().newRandomElement().getImmutable();
        Element eta = pairing.getZr().newRandomElement().getImmutable();
        Element beta = pairing.getZr().newRandomElement().getImmutable();
        Element gamma = pairing.getZr().newRandomElement().getImmutable();
        Element h = pairing.getZr().newRandomElement().getImmutable();
        Element t = pairing.getZr().newRandomElement().getImmutable();
        Element c_t = pairing.getZr().newRandomElement().getImmutable();

        Element g = pairing.getG1().newRandomElement().getImmutable();

        Element gEta = g.powZn(eta).getImmutable();      
        Element hashAID = CPABERC24Hash.ShashToZp("GN-001", pairing).powZn(t).getImmutable();   
        // Element eggAlpha = pairing.pairing(g, g).powZn(alpha).getImmutable();
        Element hAb = hashAID.mul(beta).getImmutable();
        Element hAh = hashAID.mul(h).getImmutable();
        Element hAg = hashAID.mul(gamma).getImmutable();

        Element eggAlpha = pairing.pairing(g, g).powZn(alpha).getImmutable();
        Element eggHb = pairing.pairing(g, g).powZn(hAb.div(c_t).getImmutable()).getImmutable();
        Element gHh = g.powZn(hAh.div(c_t).getImmutable()).getImmutable();
        Element gHg = g.powZn(hAg.div(c_t).getImmutable()).getImmutable();
        Element eggH = pairing.pairing(g, g).powZn(hashAID.div(c_t).getImmutable()).getImmutable();
        Element gH = g.powZn(hashAID.div(c_t).getImmutable()).getImmutable();

        return new PairingKeySerPair(
                new CPABERC24PublicKeySerParameter(this.parameters.getPairingParameters(), g, gEta, eggAlpha, eggHb, gHh, gHg, eggH, gH),
                new CPABERC24MasterSecretKeySerParameter(this.parameters.getPairingParameters(), alpha, hAb, hAh, hAg, hashAID));
    }
}
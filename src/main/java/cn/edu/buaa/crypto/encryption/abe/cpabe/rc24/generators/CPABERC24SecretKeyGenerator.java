package cn.edu.buaa.crypto.encryption.abe.cpabe.rc24.generators;

import cn.edu.buaa.crypto.algebra.generators.PairingKeyParameterGenerator;
import cn.edu.buaa.crypto.algebra.serparams.PairingKeySerParameter;
import cn.edu.buaa.crypto.encryption.abe.cpabe.genparams.CPABESecretKeyGenerationParameter;
import cn.edu.buaa.crypto.encryption.abe.cpabe.rc24.serparams.CPABERC24MasterSecretKeySerParameter;
import cn.edu.buaa.crypto.encryption.abe.cpabe.rc24.serparams.CPABERC24PublicKeySerParameter;
import cn.edu.buaa.crypto.encryption.abe.cpabe.rc24.serparams.CPABERC24SecretKeySerParameter;
import cn.edu.buaa.crypto.encryption.abe.cpabe.rc24.tools.CPABERC24Hash;
import cn.edu.buaa.crypto.utils.PairingUtils;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import org.bouncycastle.crypto.KeyGenerationParameters;

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
public class CPABERC24SecretKeyGenerator implements PairingKeyParameterGenerator {
    protected CPABESecretKeyGenerationParameter parameter;

    public void init(KeyGenerationParameters keyGenerationParameter) {
        this.parameter = (CPABESecretKeyGenerationParameter)keyGenerationParameter;
    }

    public PairingKeySerParameter generateKey() {
        CPABERC24MasterSecretKeySerParameter masterSecretKeyParameter = (CPABERC24MasterSecretKeySerParameter)parameter.getMasterSecretKeyParameter();
        CPABERC24PublicKeySerParameter publicKeyParameter = (CPABERC24PublicKeySerParameter)parameter.getPublicKeyParameter();

        String[] attributes = this.parameter.getAttributes();
        Pairing pairing = PairingFactory.getPairing(publicKeyParameter.getParameters());

        Element Sigma = pairing.getZr().newRandomElement().getImmutable();
        Map<String, Element> UAK1 = new HashMap<String, Element>();
        Element UAK2 = (publicKeyParameter.getG().powZn(masterSecretKeyParameter.getHashAID())).mul(CPABERC24Hash.ShashToG("UE01",pairing).powZn(masterSecretKeyParameter.getHashAID())).getImmutable();
        Map<String, Element> D1 = new HashMap<String, Element>();
        Element D1p = publicKeyParameter.getG().powZn(masterSecretKeyParameter.getHashAID().div(Sigma)).getImmutable();
        Element D2 = (publicKeyParameter.getG().powZn(masterSecretKeyParameter.getAlpha()).mul(publicKeyParameter.getGEta())).powZn(pairing.getZr().newOneElement().div(Sigma)).getImmutable();
        Element D3 = publicKeyParameter.getG().powZn(pairing.getZr().newOneElement().div(Sigma)).getImmutable();

        for (String attribute : attributes) {
            UAK1.put(attribute, (publicKeyParameter.getG().powZn(masterSecretKeyParameter.getHAb().get(attribute))).mul(CPABERC24Hash.ShashToG("UE01",pairing).powZn(masterSecretKeyParameter.getHAg().get(attribute))).getImmutable());
            D1.put(attribute, publicKeyParameter.getG().powZn(masterSecretKeyParameter.getHAh().get(attribute).div(Sigma)).getImmutable());
        }
        return new CPABERC24SecretKeySerParameter(publicKeyParameter.getParameters(), Sigma, UAK1, UAK2, D1, D1p, D2, D3);
    }
}

package cn.edu.buaa.crypto.encryption.abe.cpabe.rc24.serparams;

import cn.edu.buaa.crypto.algebra.serparams.PairingKeySerParameter;
import cn.edu.buaa.crypto.utils.PairingUtils;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

import java.util.Arrays;

/**
 * Created by Weiran Liu on 2016/11/29.
 *
 * Rouselakis-Waters CP-ABE master secret key parameter.
 */
public class CPABERC24MasterSecretKeySerParameter extends PairingKeySerParameter {
    private transient Element alpha;
    private final byte[] byteArrayAlpha;

    private transient Element hAb;
    private final byte[] byteArrayHAb;

    private transient Element hAh;
    private final byte[] byteArrayHAh;

    private transient Element hAg;
    private final byte[] byteArrayHAg;

    private transient Element hashAID;
    private final byte[] byteArrayHashAID;

    public CPABERC24MasterSecretKeySerParameter(PairingParameters pairingParameters, Element alpha, Element hAb, Element hAh, Element hAg, Element hashAID) {
        super(true, pairingParameters);
        this.alpha = alpha.getImmutable();
        this.byteArrayAlpha = this.alpha.toBytes();

        this.hAb = hAb.getImmutable();
        this.byteArrayHAb = this.hAb.toBytes();

        this.hAh = hAh.getImmutable();
        this.byteArrayHAh = this.hAh.toBytes();

        this.hAg = hAg.getImmutable();
        this.byteArrayHAg = this.hAg.toBytes();

        this.hashAID = hashAID.getImmutable();
        this.byteArrayHashAID = this.hashAID.toBytes();
    }

    public Element getAlpha() { return this.alpha.duplicate(); }
    public Element getHAb() { return this.hAb.duplicate(); }
    public Element getHAh() { return this.hAh.duplicate(); }
    public Element getHAg() { return this.hAg.duplicate(); }
    public Element getHashAID() { return this.hashAID.duplicate(); }

    @Override
    public boolean equals(Object anObject) {
        if (this == anObject) {
            return true;
        }
        if (anObject instanceof CPABERC24MasterSecretKeySerParameter) {
            CPABERC24MasterSecretKeySerParameter that = (CPABERC24MasterSecretKeySerParameter)anObject;
            //compare alpha
            if (!(PairingUtils.isEqualElement(this.alpha, that.alpha))) {
                return false;
            }
            if (!Arrays.equals(this.byteArrayAlpha, that.byteArrayAlpha)) {
                return false;
            }
            //compare hAb
            if (!(PairingUtils.isEqualElement(this.hAb, that.hAb))) {
                return false;
            }
            if (!Arrays.equals(this.byteArrayHAb, that.byteArrayHAb)) {
                return false;
            }
            //compare hAh
            if (!(PairingUtils.isEqualElement(this.hAh, that.hAh))) {
                return false;
            }
            if (!Arrays.equals(this.byteArrayHAh, that.byteArrayHAh)) {
                return false;
            }
            //compare hAg
            if (!(PairingUtils.isEqualElement(this.hAg, that.hAg))) {
                return false;
            }
            if (!Arrays.equals(this.byteArrayHAg, that.byteArrayHAg)) {
                return false;
            }
            //compare hashAID
            if (!(PairingUtils.isEqualElement(this.hashAID, that.hashAID))) {
                return false;
            }
            if (!Arrays.equals(this.byteArrayHashAID, that.byteArrayHashAID)) {
                return false;
            }
            //Compare Pairing Parameters
            return this.getParameters().toString().equals(that.getParameters().toString());
        }
        return false;
    }

    private void readObject(java.io.ObjectInputStream objectInputStream)
            throws java.io.IOException, ClassNotFoundException {
        objectInputStream.defaultReadObject();
        Pairing pairing = PairingFactory.getPairing(this.getParameters());
        this.alpha = pairing.getZr().newElementFromBytes(this.byteArrayAlpha).getImmutable();
        this.hAb = pairing.getZr().newElementFromBytes(this.byteArrayHAb).getImmutable();
        this.hAh = pairing.getZr().newElementFromBytes(this.byteArrayHAh).getImmutable();
        this.hAg = pairing.getZr().newElementFromBytes(this.byteArrayHAg).getImmutable();
        this.hashAID = pairing.getZr().newElementFromBytes(this.byteArrayHashAID).getImmutable();
    }
}

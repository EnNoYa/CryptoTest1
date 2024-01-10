package cn.edu.buaa.crypto.encryption.abe.cpabe.rc24.serparams;

import cn.edu.buaa.crypto.algebra.serparams.PairingKeySerParameter;
import cn.edu.buaa.crypto.utils.PairingUtils;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

/**
 * Created by Weiran Liu on 2016/11/29.
 *
 * Rouselakis-Waters CP-ABE master secret key parameter.
 */
public class CPABERC24MasterSecretKeySerParameter extends PairingKeySerParameter {
    private transient Element alpha;
    private final byte[] byteArrayAlpha;

    // private transient Element hAb;
    // private final byte[] byteArrayHAb;
    private transient Map<String, Element> hAb;
    private final Map<String, byte[]> byteArraysHAb;

    // private transient Element hAh;
    // private final byte[] byteArrayHAh;
    private transient Map<String, Element> hAh;
    private final Map<String, byte[]> byteArraysHAh;

    // private transient Element hAg;
    // private final byte[] byteArrayHAg;
    private transient Map<String, Element> hAg;
    private final Map<String, byte[]> byteArraysHAg;

    private transient Element hashAID;
    private final byte[] byteArrayHashAID;
    // private transient Map<String, Element> hashAID;
    // private final Map<String, byte[]> byteArraysHashAID;

    public CPABERC24MasterSecretKeySerParameter(PairingParameters pairingParameters, Element alpha, Map<String, Element> hAb, Map<String, Element> hAh, Map<String, Element> hAg, Element hashAID) {
        super(true, pairingParameters);
        this.alpha = alpha.getImmutable();
        this.byteArrayAlpha = this.alpha.toBytes();

        // this.hAb = hAb.getImmutable();
        // this.byteArrayHAb = this.hAb.toBytes();
        this.hAb = new HashMap<String, Element>();
        this.byteArraysHAb = new HashMap<String, byte[]>();

        // this.hAh = hAh.getImmutable();
        // this.byteArrayHAh = this.hAh.toBytes();
        this.hAh = new HashMap<String, Element>();
        this.byteArraysHAh = new HashMap<String, byte[]>();

        // this.hAg = hAg.getImmutable();
        // this.byteArrayHAg = this.hAg.toBytes();
        this.hAg = new HashMap<String, Element>();
        this.byteArraysHAg = new HashMap<String, byte[]>();

        this.hashAID = hashAID.getImmutable();
        this.byteArrayHashAID = this.hashAID.toBytes();
        // this.hashAID = new HashMap<String, Element>();
        // this.byteArraysHashAID = new HashMap<String, byte[]>();

        for (String attribute : hAb.keySet()) {
            this.hAb.put(attribute, hAb.get(attribute).duplicate().getImmutable());
            this.byteArraysHAb.put(attribute, hAb.get(attribute).duplicate().getImmutable().toBytes());
            this.hAh.put(attribute, hAh.get(attribute).duplicate().getImmutable());
            this.byteArraysHAh.put(attribute, hAh.get(attribute).duplicate().getImmutable().toBytes());
            this.hAg.put(attribute, hAg.get(attribute).duplicate().getImmutable());
            this.byteArraysHAg.put(attribute, hAg.get(attribute).duplicate().getImmutable().toBytes());
            // this.hashAID.put(attribute, hashAID.get(attribute).duplicate().getImmutable());
            // this.byteArraysHashAID.put(attribute, hashAID.get(attribute).duplicate().getImmutable().toBytes());
        }
    }
    public String[] getAttributes() { return this.hAb.keySet().toArray(new String[1]); }
    public Element getAlpha() { return this.alpha.duplicate(); }
    // public Element getHAb() { return this.hAb.duplicate(); }
    public Map<String, Element> getHAb() { return this.hAb; }
    public Element getHAbAt(String attribute) { return this.hAb.get(attribute).duplicate(); }

    // public Element getHAh() { return this.hAh.duplicate(); }
    public Map<String, Element> getHAh() { return this.hAh; }
    public Element getHAhAt(String attribute) { return this.hAh.get(attribute).duplicate(); }

    // public Element getHAg() { return this.hAg.duplicate(); }
    public Map<String, Element> getHAg() { return this.hAg; }
    public Element getHAgAt(String attribute) { return this.hAg.get(attribute).duplicate(); }

    public Element getHashAID() { return this.hashAID.duplicate(); }
    // public Map<String, Element> getHashAID() { return this.hashAID; }
    // public Element getHashAIDAt(String attribute) { return this.hashAID.get(attribute).duplicate(); }


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
            // if (!(PairingUtils.isEqualElement(this.hAb, that.hAb))) {
            //     return false;
            // }
            // if (!Arrays.equals(this.byteArrayHAb, that.byteArrayHAb)) {
            //     return false;
            // }
            if (!this.hAb.equals(that.hAb)) {
                return false;
            }
            if (!PairingUtils.isEqualByteArrayMaps(this.byteArraysHAb, that.byteArraysHAb)) {
                return false;
            }
            //compare hAh
            // if (!(PairingUtils.isEqualElement(this.hAh, that.hAh))) {
            //     return false;
            // }
            // if (!Arrays.equals(this.byteArrayHAh, that.byteArrayHAh)) {
            //     return false;
            // }
            if (!this.hAh.equals(that.hAh)) {
                return false;
            }
            if (!PairingUtils.isEqualByteArrayMaps(this.byteArraysHAh, that.byteArraysHAh)) {
                return false;
            }
            //compare hAg
            // if (!(PairingUtils.isEqualElement(this.hAg, that.hAg))) {
            //     return false;
            // }
            // if (!Arrays.equals(this.byteArrayHAg, that.byteArrayHAg)) {
            //     return false;
            // }
            if (!this.hAg.equals(that.hAg)) {
                return false;
            }
            if (!PairingUtils.isEqualByteArrayMaps(this.byteArraysHAg, that.byteArraysHAg)) {
                return false;
            }
            // compare hashAID
            if (!(PairingUtils.isEqualElement(this.hashAID, that.hashAID))) {
                return false;
            }
            if (!Arrays.equals(this.byteArrayHashAID, that.byteArrayHashAID)) {
                return false;
            }
            // if (!this.hashAID.equals(that.hashAID)) {
            //     return false;
            // }
            // if (!PairingUtils.isEqualByteArrayMaps(this.byteArraysHashAID, that.byteArraysHashAID)) {
            //     return false;
            // }
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
        // this.hAb = pairing.getZr().newElementFromBytes(this.byteArrayHAb).getImmutable();
        // this.hAh = pairing.getZr().newElementFromBytes(this.byteArrayHAh).getImmutable();
        // this.hAg = pairing.getZr().newElementFromBytes(this.byteArrayHAg).getImmutable();
        this.hashAID = pairing.getZr().newElementFromBytes(this.byteArrayHashAID).getImmutable();
        this.hAb = new HashMap<String, Element>();
        this.hAh = new HashMap<String, Element>();
        this.hAg = new HashMap<String, Element>();
        // this.hashAID = new HashMap<String, Element>();
        for (String attribute : this.byteArraysHAb.keySet()) {
            this.hAb.put(attribute, pairing.getZr().newElementFromBytes(this.byteArraysHAb.get(attribute)).getImmutable());
            this.hAh.put(attribute, pairing.getZr().newElementFromBytes(this.byteArraysHAh.get(attribute)).getImmutable());
            this.hAg.put(attribute, pairing.getZr().newElementFromBytes(this.byteArraysHAg.get(attribute)).getImmutable());
            // this.hashAID.put(attribute, pairing.getZr().newElementFromBytes(this.byteArraysHashAID.get(attribute)).getImmutable());
 
        }
    }
}

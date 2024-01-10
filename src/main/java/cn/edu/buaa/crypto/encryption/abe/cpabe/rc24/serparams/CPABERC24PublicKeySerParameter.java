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
 * Edited by ENY 
 * 
 * Reference:
 *
 * Created by Weiran Liu on 2016/11/29.
 *
 * Rouselakis-Waters CP-ABE public key / master secret key generator.
 */
public class CPABERC24PublicKeySerParameter extends PairingKeySerParameter {
    public transient Element g;
    private final byte[] byteArrayG;

    private transient Element gEta;
    private final byte[] byteArrayGEta;

    private transient Element eggAlpha;
    private final byte[] byteArrayEggAlpha;

    private transient Map<String, Element> eggHb;
    private final Map<String, byte[]> byteArraysEggHb;

    private transient Map<String, Element> gHh;
    private final Map<String, byte[]> byteArraysGHh;

    private transient Map<String, Element> gHg;
    private final Map<String, byte[]> byteArraysGHg;

    // private transient Map<String, Element> eggH;
    // private final Map<String, byte[]> byteArraysEggH;
    private transient Element eggH;
    private final byte[] byteArrayEggH;

    // private transient Map<String, Element> gH;
    // private final Map<String, byte[]> byteArraysGH;
    private transient Element gH;
    private final byte[] byteArrayGH;

    public transient Element ct;
    private final byte[] byteArrayCt;

    public CPABERC24PublicKeySerParameter(
            PairingParameters parameters, Element g, Element gEta, Element eggAlpha, Map<String, Element> eggHb, Map<String, Element> gHh, Map<String, Element> gHg, Element eggH, Element gH, Element ct) {
        super(false, parameters);

        // GP
        this.g = g.getImmutable();
        this.byteArrayG = this.g.toBytes();

        this.gEta = gEta.getImmutable();
        this.byteArrayGEta = this.gEta.toBytes();

        // APK
        this.eggAlpha = eggAlpha.getImmutable();
        this.byteArrayEggAlpha = this.eggAlpha.toBytes();

        this.eggHb = new HashMap<String, Element>();
        this.byteArraysEggHb = new HashMap<String, byte[]>();

        this.gHh = new HashMap<String, Element>();
        this.byteArraysGHh = new HashMap<String, byte[]>();

        this.gHg = new HashMap<String, Element>();
        this.byteArraysGHg = new HashMap<String, byte[]>();

        // this.eggH = new HashMap<String, Element>();
        // this.byteArraysEggH = new HashMap<String, byte[]>();
        this.eggH = eggH.getImmutable();
        this.byteArrayEggH = this.eggH.toBytes();

        // this.gH = new HashMap<String, Element>();
        // this.byteArraysGH = new HashMap<String, byte[]>();
        this.gH = gH.getImmutable();
        this.byteArrayGH = this.gH.toBytes();

        this.ct = ct.getImmutable();
        this.byteArrayCt = this.ct.toBytes();

        for (String attribute : eggHb.keySet()) {
            this.eggHb.put(attribute, eggHb.get(attribute).duplicate().getImmutable());
            this.byteArraysEggHb.put(attribute, eggHb.get(attribute).duplicate().getImmutable().toBytes());
            this.gHh.put(attribute, gHh.get(attribute).duplicate().getImmutable());
            this.byteArraysGHh.put(attribute, gHh.get(attribute).duplicate().getImmutable().toBytes());
            this.gHg.put(attribute, gHg.get(attribute).duplicate().getImmutable());
            this.byteArraysGHg.put(attribute, gHg.get(attribute).duplicate().getImmutable().toBytes());
            // this.eggH.put(attribute, eggH.get(attribute).duplicate().getImmutable());
            // this.byteArraysEggH.put(attribute, eggH.get(attribute).duplicate().getImmutable().toBytes());
            // this.gH.put(attribute, gH.get(attribute).duplicate().getImmutable());
            // this.byteArraysGH.put(attribute, gH.get(attribute).duplicate().getImmutable().toBytes());
     
        }

    }
    public String[] getAttributes() { return this.eggHb.keySet().toArray(new String[1]); }
    public Element getG() { return this.g.duplicate(); }

    public Element getGEta() { return this.gEta.duplicate(); }

    // public Element getEggHb() { return this.eggHb.duplicate(); }
    public Map<String, Element> getEggHb() { return this.eggHb; }
    public Element getEggHbAt(String attribute) { return this.eggHb.get(attribute).duplicate(); }


    // public Element getGHh() { return this.gHh.duplicate(); }
    public Map<String, Element> getGHh() { return this.gHh; }
    public Element getGHhAt(String attribute) { return this.gHh.get(attribute).duplicate(); }


    // public Element getGHg() { return this.gHg.duplicate(); }
    public Map<String, Element> getGHg() { return this.gHg; }
    public Element getGHgAt(String attribute) { return this.gHg.get(attribute).duplicate(); }

    public Element getEggAlpha() { return this.eggAlpha.duplicate(); }

    public Element getEggH() { return this.eggH.duplicate(); }
    // public Map<String, Element> getEggH() { return this.eggH; }
    // public Element getEggHAt(String attribute) { return this.eggH.get(attribute).duplicate(); }

    public Element getGH() { return this.gH.duplicate(); }
    // public Map<String, Element> getGH() { return this.gH; }
    // public Element getGHAt(String attribute) { return this.gH.get(attribute).duplicate(); }
    public Element getCt() { return this.ct.duplicate(); }

    @Override
    public boolean equals(Object anObject) {
        if (this == anObject) {
            return true;
        }
        if (anObject instanceof CPABERC24PublicKeySerParameter) {
            CPABERC24PublicKeySerParameter that = (CPABERC24PublicKeySerParameter)anObject;
            //Compare g
            if (!PairingUtils.isEqualElement(this.g, that.g)) {
                return false;
            }
            if (!Arrays.equals(this.byteArrayG, that.byteArrayG)) {
                return false;
            }
            //Compare gEta
            if (!PairingUtils.isEqualElement(this.gEta, that.gEta)) {
                return false;
            }
            if (!Arrays.equals(this.byteArrayGEta, that.byteArrayGEta)) {
                return false;
            }
            //Compare eggHb
            if (!this.eggHb.equals(that.eggHb)) {
                return false;
            }
            if (!PairingUtils.isEqualByteArrayMaps(this.byteArraysEggHb, that.byteArraysEggHb)) {
                return false;
            }
            //Compare gHh
            if (!this.gHh.equals(that.gHh)) {
                return false;
            }
            if (!PairingUtils.isEqualByteArrayMaps(this.byteArraysGHh, that.byteArraysGHh)) {
                return false;
            }
            //Compare gHg
            if (!this.gHg.equals(that.gHg)) {
                return false;
            }
            if (!PairingUtils.isEqualByteArrayMaps(this.byteArraysGHg, that.byteArraysGHg)) {
                return false;
            }
            //Compare eggAlpha
            if (!PairingUtils.isEqualElement(this.eggAlpha, that.eggAlpha)) {
                return false;
            }
            if (!Arrays.equals(this.byteArrayEggAlpha, that.byteArrayEggAlpha)) {
                return false;
            }
            //Compare eggH
            // if (!this.eggH.equals(that.eggH)) {
            //     return false;
            // }
            // if (!PairingUtils.isEqualByteArrayMaps(this.byteArraysEggH, that.byteArraysEggH)) {
            //     return false;
            // }
            if (!PairingUtils.isEqualElement(this.eggH, that.eggH)) {
                return false;
            }
            if (!Arrays.equals(this.byteArrayEggH, that.byteArrayEggH)) {
                return false;
            }
            //Compare gH
            // if (!this.gH.equals(that.gH)) {
            //     return false;
            // }
            // if (!PairingUtils.isEqualByteArrayMaps(this.byteArraysGH, that.byteArraysGH)) {
            //     return false;
            // }
            if (!PairingUtils.isEqualElement(this.gH, that.gH)) {
                return false;
            }
            if (!Arrays.equals(this.byteArrayGH, that.byteArrayGH)) {
                return false;
            }
            if (!PairingUtils.isEqualElement(this.ct, that.ct)) {
                return false;
            }
            if (!Arrays.equals(this.byteArrayCt, that.byteArrayCt)) {
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
        this.g = pairing.getG1().newElementFromBytes(this.byteArrayG).getImmutable();
        this.gEta = pairing.getG1().newElementFromBytes(this.byteArrayGEta).getImmutable();
        // this.eggHb = pairing.getGT().newElementFromBytes(this.byteArrayEggHb).getImmutable();
        // this.gHh = pairing.getG1().newElementFromBytes(this.byteArrayGHh).getImmutable();
        // this.gHg = pairing.getG1().newElementFromBytes(this.byteArrayGHg).getImmutable();
        this.eggAlpha = pairing.getGT().newElementFromBytes(this.byteArrayEggAlpha).getImmutable();
        this.eggH = pairing.getGT().newElementFromBytes(this.byteArrayEggH).getImmutable();
        this.gH = pairing.getG1().newElementFromBytes(this.byteArrayGH).getImmutable();
        this.eggHb = new HashMap<String, Element>();
        this.gHh = new HashMap<String, Element>();
        this.gHg = new HashMap<String, Element>();
        // this.eggH = new HashMap<String, Element>();
        // this.gH = new HashMap<String, Element>();
        for (String attribute : this.byteArraysEggHb.keySet()) {
            this.eggHb.put(attribute, pairing.getGT().newElementFromBytes(this.byteArraysEggHb.get(attribute)).getImmutable());
            this.gHh.put(attribute, pairing.getG1().newElementFromBytes(this.byteArraysGHh.get(attribute)).getImmutable());
            this.gHg.put(attribute, pairing.getG1().newElementFromBytes(this.byteArraysGHg.get(attribute)).getImmutable());
        //     this.eggH.put(attribute, pairing.getGT().newElementFromBytes(this.byteArraysEggH.get(attribute)).getImmutable());
        //      this.gH.put(attribute, pairing.getG1().newElementFromBytes(this.byteArraysGH.get(attribute)).getImmutable());
        }
    }
}

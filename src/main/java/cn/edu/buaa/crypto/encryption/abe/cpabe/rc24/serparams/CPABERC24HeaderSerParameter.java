package cn.edu.buaa.crypto.encryption.abe.cpabe.rc24.serparams;

import cn.edu.buaa.crypto.algebra.serparams.PairingCipherSerParameter;
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
public class CPABERC24HeaderSerParameter extends PairingCipherSerParameter {
    protected final String[] rhos;
    protected transient Element Es;
    protected final byte[] byteArrayEs;

    protected transient Element Ev;
    protected final byte[] byteArrayEv;

    protected transient Map<String, Element> E1;
    private final byte[][] byteArraysE1;

    protected transient Map<String, Element> E2;
    private final byte[][] byteArraysE2;

    protected transient Map<String, Element> E3;
    private final byte[][] byteArraysE3;

    protected transient Map<String, Element> E4;
    private final byte[][] byteArraysE4;

    public CPABERC24HeaderSerParameter(PairingParameters pairingParameters, Element Ev,
                                       Element Es, Map<String, Element> E1, Map<String, Element> E2, Map<String, Element> E3, Map<String, Element> E4) {
        super(pairingParameters);

        this.rhos = E1.keySet().toArray(new String[1]);
        this.Es = Es.getImmutable();
        this.byteArrayEs = this.Es.toBytes();
        this.Ev = Ev.getImmutable();
        this.byteArrayEv = this.Ev.toBytes();

        this.E1 = new HashMap<String, Element>();
        this.byteArraysE1 = new byte[this.rhos.length][];
        this.E2 = new HashMap<String, Element>();
        this.byteArraysE2 = new byte[this.rhos.length][];
        this.E3 = new HashMap<String, Element>();
        this.byteArraysE3 = new byte[this.rhos.length][];
        this.E4 = new HashMap<String, Element>();
        this.byteArraysE4 = new byte[this.rhos.length][];

        for (int i = 0; i < this.rhos.length; i++) {
            Element E1p = E1.get(this.rhos[i]).duplicate().getImmutable();
            this.E1.put(this.rhos[i], E1p);
            this.byteArraysE1[i] = E1p.toBytes();

            Element E2p = E2.get(this.rhos[i]).duplicate().getImmutable();
            this.E2.put(this.rhos[i], E2p);
            this.byteArraysE2[i] = E2p.toBytes();

            Element E3p = E3.get(this.rhos[i]).duplicate().getImmutable();
            this.E3.put(this.rhos[i], E3p);
            this.byteArraysE3[i] = E3p.toBytes();
                       
            Element E4p = E4.get(this.rhos[i]).duplicate().getImmutable();
            this.E4.put(this.rhos[i], E4p);
            this.byteArraysE3[i] = E4p.toBytes();
        }
    }

    public Element getEs() { return this.Es.duplicate(); }

    public Element getEv() { return this.Ev.duplicate(); }

    public Map<String, Element> getE1() { return this.E1; }

    public Element getE1At(String rho) { return this.E1.get(rho).duplicate(); }

    public Map<String, Element> getE2() { return this.E2; }

    public Element getE2At(String rho) { return this.E2.get(rho).duplicate(); }

    public Map<String, Element> getE3() { return this.E3; }

    public Element getE3At(String rho) { return this.E3.get(rho).duplicate(); }

    public Map<String, Element> getE4() { return this.E4; }

    public Element getE4At(String rho) { return this.E4.get(rho).duplicate(); }

    @Override
    public boolean equals(Object anObject) {
        if (this == anObject) {
            return true;
        }
        if (anObject instanceof CPABERC24HeaderSerParameter) {
            CPABERC24HeaderSerParameter that = (CPABERC24HeaderSerParameter)anObject;
            //Compare Es
            if (!PairingUtils.isEqualElement(this.Es, that.Es)) {
                return false;
            }
            if (!Arrays.equals(this.byteArrayEs, that.byteArrayEs)) {
                return false;
            }
            //Compare Ev
            if (!PairingUtils.isEqualElement(this.Ev, that.Ev)) {
                return false;
            }
            if (!Arrays.equals(this.byteArrayEv, that.byteArrayEv)) {
                return false;
            }
            //Compare E1
            if (!this.E1.equals(that.E1)) {
                return false;
            }
            if (!PairingUtils.isEqualByteArrays(this.byteArraysE1, that.byteArraysE1)) {
                return false;
            }
            //Compare E2
            if (!this.E2.equals(that.E2)) {
                return false;
            }
            if (!PairingUtils.isEqualByteArrays(this.byteArraysE2, that.byteArraysE2)) {
                return false;
            }
            //Compare E3
            if (!this.E3.equals(that.E3)) {
                return false;
            }
            if (!PairingUtils.isEqualByteArrays(this.byteArraysE3, that.byteArraysE3)) {
                return false;
            }
            //Compare E4
            if (!this.E4.equals(that.E4)) {
                return false;
            }
            if (!PairingUtils.isEqualByteArrays(this.byteArraysE4, that.byteArraysE4)) {
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
        this.Es = pairing.getG1().newElementFromBytes(this.byteArrayEs).getImmutable();
        this.Ev = pairing.getG1().newElementFromBytes(this.byteArrayEs).getImmutable();
        this.E1 = new HashMap<String, Element>();
        this.E2 = new HashMap<String, Element>();
        this.E3 = new HashMap<String, Element>();
        this.E4 = new HashMap<String, Element>();
        for (int i = 0; i < this.rhos.length; i++) {
            this.E1.put(this.rhos[i], pairing.getG1().newElementFromBytes(this.byteArraysE1[i]).getImmutable());
            this.E2.put(this.rhos[i], pairing.getG1().newElementFromBytes(this.byteArraysE2[i]).getImmutable());
            this.E3.put(this.rhos[i], pairing.getG1().newElementFromBytes(this.byteArraysE3[i]).getImmutable());
            this.E4.put(this.rhos[i], pairing.getG1().newElementFromBytes(this.byteArraysE4[i]).getImmutable());
        }
    }
}
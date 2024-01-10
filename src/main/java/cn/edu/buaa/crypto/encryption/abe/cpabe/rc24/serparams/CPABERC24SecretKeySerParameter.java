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
 * Rouselakis-Waters CP-ABE secret key parameter.
 */
public class CPABERC24SecretKeySerParameter extends PairingKeySerParameter {
    private transient Element Sigma;
    private final byte[] byteArraySigma;

    private transient Element UAK2;
    private final byte[] byteArrayUAK2;

    private transient Element D1p;
    private final byte[] byteArrayD1p;

    private transient Element D2;
    private final byte[] byteArrayD2;

    private transient Element D3;
    private final byte[] byteArrayD3;

    private transient Map<String, Element> UAK1;
    private final Map<String, byte[]> byteArraysUAK1;

    private transient Map<String, Element> D1;
    private final Map<String, byte[]> byteArraysD1;

    public CPABERC24SecretKeySerParameter(PairingParameters pairingParameters, Element  Sigma, Map<String, Element> UAK1, Element UAK2, Map<String, Element> D1, Element D1p, Element D2, Element D3) {
        super(true, pairingParameters);

        this.Sigma = Sigma.getImmutable();
        this.byteArraySigma = this.Sigma.toBytes();

        this.UAK2 = UAK2.getImmutable();
        this.byteArrayUAK2 = this.UAK2.toBytes();

        this.D1p = D1p.getImmutable();
        this.byteArrayD1p = this.D1p.toBytes();

        this.D2 = D2.getImmutable();
        this.byteArrayD2 = this.D2.toBytes();

        this.D3 = D3.getImmutable();
        this.byteArrayD3 = this.D3.toBytes();


        this.UAK1 = new HashMap<String, Element>();
        this.byteArraysUAK1 = new HashMap<String, byte[]>();
        this.D1 = new HashMap<String, Element>();
        this.byteArraysD1 = new HashMap<String, byte[]>();

        for (String attribute : UAK1.keySet()) {
            this.UAK1.put(attribute, UAK1.get(attribute).duplicate().getImmutable());
            this.byteArraysUAK1.put(attribute, UAK1.get(attribute).duplicate().getImmutable().toBytes());
            this.D1.put(attribute, D1.get(attribute).duplicate().getImmutable());
            this.byteArraysD1.put(attribute, D1.get(attribute).duplicate().getImmutable().toBytes());
        }
    }

    public String[] getAttributes() { return this.UAK1.keySet().toArray(new String[1]); }

    public Element getSigma() { return this.Sigma.duplicate(); }

    public Element getUAK2() { return this.UAK2.duplicate(); }
    
    public Element getD1p() { return this.D1p.duplicate(); }
    
    public Element getD2() { return this.D2.duplicate(); }
    
    public Element getD3() { return this.D3.duplicate(); }

    public Map<String, Element> getUAK1() { return this.UAK1; }

    public Element getUAK1At(String attribute) { return this.UAK1.get(attribute).duplicate(); }

    public Map<String, Element> getD1() { return this.D1; }

    public Element getD1At(String attribute) { return this.D1.get(attribute).duplicate(); }

    @Override
    public boolean equals(Object anObject) {
        if (this == anObject) {
            return true;
        }
        if (anObject instanceof CPABERC24SecretKeySerParameter) {
            CPABERC24SecretKeySerParameter that = (CPABERC24SecretKeySerParameter)anObject;
            //Compare Sigma
            if (!PairingUtils.isEqualElement(this.Sigma, that.Sigma)) {
                return false;
            }
            if (!Arrays.equals(this.byteArraySigma, that.byteArraySigma)) {
                return false;
            }
            //Compare UAK2
            if (!PairingUtils.isEqualElement(this.UAK2, that.UAK2)) {
                return false;
            }
            if (!Arrays.equals(this.byteArrayUAK2, that.byteArrayUAK2)) {
                return false;
            }
            //Compare D1p
            if (!PairingUtils.isEqualElement(this.D1p, that.D1p)) {
                return false;
            }
            if (!Arrays.equals(this.byteArrayD1p, that.byteArrayD1p)) {
                return false;
            }
            //Compare D2
            if (!PairingUtils.isEqualElement(this.D2, that.D2)) {
                return false;
            }
            if (!Arrays.equals(this.byteArrayD2, that.byteArrayD2)) {
                return false;
            }
            //Compare D3
            if (!PairingUtils.isEqualElement(this.D3, that.D3)) {
                return false;
            }
            if (!Arrays.equals(this.byteArrayD3, that.byteArrayD3)) {
                return false;
            }
            //compare UAK1
            if (!this.UAK1.equals(that.UAK1)) {
                return false;
            }
            if (!PairingUtils.isEqualByteArrayMaps(this.byteArraysUAK1, that.byteArraysUAK1)) {
                return false;
            }
            //compare D1
            if (!this.D1.equals(that.D1)) {
                return false;
            }
            if (!PairingUtils.isEqualByteArrayMaps(this.byteArraysD1, that.byteArraysD1)) {
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
        this.Sigma = pairing.getG1().newElementFromBytes(this.byteArraySigma);
        this.UAK2 = pairing.getG1().newElementFromBytes(this.byteArrayUAK2);
        this.D1p = pairing.getG1().newElementFromBytes(this.byteArrayD1p);
        this.D2 = pairing.getG1().newElementFromBytes(this.byteArrayD2);
        this.D3 = pairing.getG1().newElementFromBytes(this.byteArrayD3);
        this.UAK1 = new HashMap<String, Element>();
        this.D1 = new HashMap<String, Element>();
        for (String attribute : this.byteArraysUAK1.keySet()) {
            this.UAK1.put(attribute, pairing.getG1().newElementFromBytes(this.byteArraysUAK1.get(attribute)).getImmutable());
            this.D1.put(attribute, pairing.getG1().newElementFromBytes(this.byteArraysD1.get(attribute)).getImmutable());
        }
    }
}
package cn.edu.buaa.crypto.encryption.abe.cpabe.rc24.serparams;

import cn.edu.buaa.crypto.algebra.serparams.PairingKeySerParameter;
import cn.edu.buaa.crypto.utils.PairingUtils;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

import java.util.Arrays;

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

    private transient Element eggHb;
    private final byte[] byteArrayEggHb;

    private transient Element gHh;
    private final byte[] byteArrayGHh;

    private transient Element gHg;
    private final byte[] byteArrayGHg;

    private transient Element eggH;
    private final byte[] byteArrayEggH;

    private transient Element gH;
    private final byte[] byteArrayGH;

    public CPABERC24PublicKeySerParameter(
            PairingParameters parameters, Element g, Element gEta, Element eggAlpha, Element eggHb, Element gHh, Element gHg, Element eggH, Element gH) {
        super(false, parameters);

        // GP
        this.g = g.getImmutable();
        this.byteArrayG = this.g.toBytes();

        this.gEta = gEta.getImmutable();
        this.byteArrayGEta = this.gEta.toBytes();

        // APK
        this.eggAlpha = eggAlpha.getImmutable();
        this.byteArrayEggAlpha = this.eggAlpha.toBytes();

        this.eggHb = eggHb.getImmutable();
        this.byteArrayEggHb = this.eggHb.toBytes();

        this.gHh = gHh.getImmutable();
        this.byteArrayGHh = this.gHh.toBytes();

        this.gHg = gHg.getImmutable();
        this.byteArrayGHg = this.gHg.toBytes();

        this.eggH = eggH.getImmutable();
        this.byteArrayEggH = this.eggH.toBytes();

        this.gH = gH.getImmutable();
        this.byteArrayGH = this.gH.toBytes();



    }

    public Element getG() { return this.g.duplicate(); }

    public Element getGEta() { return this.gEta.duplicate(); }

    public Element getEggHb() { return this.eggHb.duplicate(); }

    public Element getGHh() { return this.gHh.duplicate(); }

    public Element getGHg() { return this.gHg.duplicate(); }

    public Element getEggAlpha() { return this.eggAlpha.duplicate(); }

    public Element getEggH() { return this.eggH.duplicate(); }

    public Element getGH() { return this.gH.duplicate(); }


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
            if (!PairingUtils.isEqualElement(this.eggHb, that.eggHb)) {
                return false;
            }
            if (!Arrays.equals(this.byteArrayEggHb, that.byteArrayEggHb)) {
                return false;
            }
            //Compare gHh
            if (!PairingUtils.isEqualElement(this.gHh, that.gHh)) {
                return false;
            }
            if (!Arrays.equals(this.byteArrayGHh, that.byteArrayGHh)) {
                return false;
            }
            //Compare gHg
            if (!PairingUtils.isEqualElement(this.gHg, that.gHg)) {
                return false;
            }
            if (!Arrays.equals(this.byteArrayGHg, that.byteArrayGHg)) {
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
            if (!PairingUtils.isEqualElement(this.eggH, that.eggH)) {
                return false;
            }
            if (!Arrays.equals(this.byteArrayEggH, that.byteArrayEggH)) {
                return false;
            }
            //Compare gH
            if (!PairingUtils.isEqualElement(this.gH, that.gH)) {
                return false;
            }
            if (!Arrays.equals(this.byteArrayGH, that.byteArrayGH)) {
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
        this.eggHb = pairing.getGT().newElementFromBytes(this.byteArrayEggHb).getImmutable();
        this.gHh = pairing.getG1().newElementFromBytes(this.byteArrayGHh).getImmutable();
        this.gHg = pairing.getG1().newElementFromBytes(this.byteArrayGHg).getImmutable();
        this.eggAlpha = pairing.getGT().newElementFromBytes(this.byteArrayEggAlpha).getImmutable();
        this.eggH = pairing.getGT().newElementFromBytes(this.byteArrayEggH).getImmutable();
        this.gH = pairing.getG1().newElementFromBytes(this.byteArrayGH).getImmutable();
    }
}

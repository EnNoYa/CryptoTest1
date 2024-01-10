package cn.edu.buaa.crypto.encryption.abe.cpabe.rc24.serparams;

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
 * Rouselakis-Waters CP-ABE ciphertext parameter.
 */
public class CPABERC24CiphertextSerParameter extends CPABERC24HeaderSerParameter {
    private transient Element C;
    private final byte[] byteArrayC;

    public CPABERC24CiphertextSerParameter(PairingParameters pairingParameters, Element Em, Element Ev,
            Element Es, Map<String, Element> E1, Map<String, Element> E2, Map<String, Element> E3, Map<String, Element> E4) {
        super(pairingParameters, Ev, Es, E1, E2, E3, E4);

        this.C = C.getImmutable();
        this.byteArrayC = this.C.toBytes();
    }

    public Element getC() { return this.C.duplicate(); }

    @Override
    public boolean equals(Object anObject) {
        if (this == anObject) {
            return true;
        }
        if (anObject instanceof CPABERC24CiphertextSerParameter) {
            CPABERC24CiphertextSerParameter that = (CPABERC24CiphertextSerParameter) anObject;
            return PairingUtils.isEqualElement(this.C, that.C)
                    && Arrays.equals(this.byteArrayC, that.byteArrayC)
                    && super.equals(anObject);
        }
        return false;
    }

    private void readObject(java.io.ObjectInputStream objectInputStream)
            throws java.io.IOException, ClassNotFoundException {
        objectInputStream.defaultReadObject();
        Pairing pairing = PairingFactory.getPairing(this.getParameters());
        this.C = pairing.getGT().newElementFromBytes(this.byteArrayC).getImmutable();
    }
}
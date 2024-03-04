package cn.edu.buaa.crypto.algebra.serparams;

import it.unisa.dia.gas.jpbc.PairingParameters;
import org.bouncycastle.crypto.CipherParameters;
import org.json.JSONObject;

import cn.edu.buaa.crypto.encryption.abe.cpabe.rc24.tools.Converter;

import java.io.Serializable;

/**
 * Created by Weiran Liu on 15-9-30.
 *
 * Generic pairing-based ciphertext parameters.
 */
public class PairingCipherSerParameter implements CipherParameters, Serializable {

    private PairingParameters parameters;

    public PairingCipherSerParameter(PairingParameters parameters) {
        this.parameters = parameters;
    }

    public PairingParameters getParameters() {
        return parameters;
    }

    public String exportJSONstring() throws Exception{
        JSONObject json = new JSONObject();
        json.put("Param", Converter.encodeObject(getParameters()));
        return json.toString();
    }

    @Override
    public boolean equals(Object anOjbect) {
        if (this == anOjbect) {
            return true;
        }
        if (anOjbect instanceof PairingCipherSerParameter) {
            PairingCipherSerParameter that = (PairingCipherSerParameter)anOjbect;
            //Compare Pairing Parameters
            return this.getParameters().toString().equals(that.getParameters().toString());
        }
        return false;
    }
}

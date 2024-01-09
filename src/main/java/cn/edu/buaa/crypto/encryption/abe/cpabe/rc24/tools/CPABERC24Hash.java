package cn.edu.buaa.crypto.encryption.abe.cpabe.rc24.tools;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
// import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import it.unisa.dia.gas.jpbc.Field;
// import it.unisa.dia.gas.plaf.jpbc.field.z.ZrField;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.nio.charset.StandardCharsets;


/**
 * Generated by ChatGPT on 2024/01/09.
 */

public class CPABERC24Hash {

    // public static void main(String[] args, Pairing pairing) {
       
    //     // Example usage
    //     String inputString = "Hello, world!";
    //     Element hashToG = ShashToG(inputString, pairing);
    //     Element hashToGT = GthashToZp(hashToG, pairing);
    //     Element hashToZp = ShashToZp(inputString, pairing);

    //     System.out.println("String hash to G: " + hashToG.toString());
    //     System.out.println("G_t hash to Z_p: " + hashToGT.toString());
    //     System.out.println("String hash to Z_p: " + hashToZp.toString());
    // }

    // Hash a string to G
    public static Element ShashToG(String input, Pairing pairing) {
        Element g = pairing.getG1().newRandomElement().getImmutable(); // Generator in G
        Element result = g.duplicate().setFromHash(input.getBytes(StandardCharsets.UTF_8), 0, input.length());
        return result;
    }

    // Hash an element in G_T to Z_p
    public static Element GthashToZp(Element element, Pairing pairing) {
        Field<?> zpField = pairing.getZr();
        byte[] bytes = element.toBytes();
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hashedBytes = digest.digest(bytes);
            return zpField.newElementFromBytes(hashedBytes);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            return null;
        }
    }
  
    // Hash a string to Z_p
    public static Element ShashToZp(String input, Pairing pairing) {
        Field<?> zpField = pairing.getZr();
        byte[] bytes = input.getBytes(StandardCharsets.UTF_8);
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hashedBytes = digest.digest(bytes);
            return zpField.newElementFromBytes(hashedBytes);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            return null;
        }
    }

}

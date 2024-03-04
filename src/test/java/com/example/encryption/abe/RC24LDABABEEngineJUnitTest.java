package com.example.encryption.abe;

import cn.edu.buaa.crypto.access.lsss.lw10.LSSSLW10Engine;
import cn.edu.buaa.crypto.access.parser.ParserUtils;
import cn.edu.buaa.crypto.access.tree.AccessTreeEngine;
import cn.edu.buaa.crypto.algebra.serparams.*;
import cn.edu.buaa.crypto.encryption.abe.cpabe.rc24.CPABERC24Engine;
import com.example.TestUtils;
import com.example.access.AccessPolicyExamples;
import com.example.access.AccessGlobalSetExamples;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import junit.framework.TestCase;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.json.JSONObject;
import org.junit.Assert;

import java.io.IOException;
import java.security.InvalidParameterException;
import java.security.SecureRandom;
import java.util.Arrays;

import cn.edu.buaa.crypto.encryption.abe.cpabe.rc24.generators.CPABERC24EncryptionGenerator.preCiphertextPack;
import cn.edu.buaa.crypto.encryption.abe.cpabe.rc24.generators.CPABERC24KeyPairGenerator;
import cn.edu.buaa.crypto.encryption.abe.cpabe.rc24.serparams.CPABERC24SecretKeySerParameter;
import cn.edu.buaa.crypto.encryption.abe.cpabe.rc24.serparams.CPABERC24PublicKeySerParameter;

/**
 * Created by Weiran Liu on 2016/11/21.
 *
 * CP-ABE engine test.
 */
public class RC24LDABABEEngineJUnitTest extends TestCase {
    private CPABERC24Engine engine;

    private void try_valid_access_policy(Pairing pairing, PairingKeySerParameter publicKey, PairingKeySerParameter masterKey,
                                         final String accessPolicyString, final String[] attributes) {
        try {
            int[][] accessPolicy = ParserUtils.GenerateAccessPolicy(accessPolicyString);
            String[] rhos = ParserUtils.GenerateRhos(accessPolicyString);
            try_access_policy(pairing, publicKey, masterKey, accessPolicy, rhos, attributes);
        } catch (Exception e) {
            System.out.println("Access policy satisfied test failed, " +
                    "access policy = " + accessPolicyString + ", " +
                    "attributes = " + Arrays.toString(attributes));
            e.printStackTrace();
            System.exit(1);
        }
    }
    private void try_decentral_valid_access_policy(Pairing pairing, PairingKeySerParameter publicKey, PairingKeySerParameter masterKey,
                                         final String accessPolicyString, final String[] attributes) {
        try {
            int[][] accessPolicy = ParserUtils.GenerateAccessPolicy(accessPolicyString);
            String[] rhos = ParserUtils.GenerateRhos(accessPolicyString);
            try_decentral_access_policy(pairing, publicKey, masterKey, accessPolicy, rhos, attributes);
        } catch (Exception e) {
            System.out.println("Access policy satisfied test failed, " +
                    "access policy = " + accessPolicyString + ", " +
                    "attributes = " + Arrays.toString(attributes));
            e.printStackTrace();
            System.exit(1);
        }
    }
    

    private void try_valid_access_policy(Pairing pairing, PairingKeySerParameter publicKey, PairingKeySerParameter masterKey,
                                         final int[][] accessPolicy, final String[] rhos, final String[] attributes) {
        try {
            try_access_policy(pairing, publicKey, masterKey, accessPolicy, rhos, attributes);
        } catch (Exception e) {
            System.out.println("Access policy satisfied test failed, " +
                    "attributes = " + Arrays.toString(attributes));
            e.printStackTrace();
            System.exit(1);
        }
    }
    private void try_decentral_valid_access_policy(Pairing pairing, PairingKeySerParameter publicKey, PairingKeySerParameter masterKey,
                                         final int[][] accessPolicy, final String[] rhos, final String[] attributes) {
        try {
            try_decentral_access_policy(pairing, publicKey, masterKey, accessPolicy, rhos, attributes);
        } catch (Exception e) {
            System.out.println("Access policy satisfied test failed, " +
                    "attributes = " + Arrays.toString(attributes));
            e.printStackTrace();
            System.exit(1);
        }
    }
    private void try_invalid_access_policy(Pairing pairing, PairingKeySerParameter publicKey, PairingKeySerParameter masterKey,
                                           final String accessPolicyString, final String[] attributes) {
        try {
            int[][] accessPolicy = ParserUtils.GenerateAccessPolicy(accessPolicyString);
            String[] rhos = ParserUtils.GenerateRhos(accessPolicyString);
            try_access_policy(pairing, publicKey, masterKey, accessPolicy, rhos, attributes);
        } catch (InvalidCipherTextException e) {
            //correct, expected exception, nothing to do.
        } catch (Exception e) {
            System.out.println("Access policy satisfied test failed, " +
                    "access policy = " + accessPolicyString + ", " +
                    "attributes = " + Arrays.toString(attributes));
            e.printStackTrace();
            System.exit(1);
        }
    }
    private void try_decentral_invalid_access_policy(Pairing pairing, PairingKeySerParameter publicKey, PairingKeySerParameter masterKey,
                                           final String accessPolicyString, final String[] attributes) {
        try {
            int[][] accessPolicy = ParserUtils.GenerateAccessPolicy(accessPolicyString);
            String[] rhos = ParserUtils.GenerateRhos(accessPolicyString);
            try_decentral_access_policy(pairing, publicKey, masterKey, accessPolicy, rhos, attributes);
        } catch (InvalidCipherTextException e) {
            //correct, expected exception, nothing to do.
        } catch (Exception e) {
            System.out.println("Access policy satisfied test failed, " +
                    "access policy = " + accessPolicyString + ", " +
                    "attributes = " + Arrays.toString(attributes));
            e.printStackTrace();
            System.exit(1);
        }
    }

    private void try_invalid_access_policy(Pairing pairing, PairingKeySerParameter publicKey, PairingKeySerParameter masterKey,
                                           final int[][] accessPolicy, final String[] rhos, final String[] attributes) {
        try {
            try_access_policy(pairing, publicKey, masterKey, accessPolicy, rhos, attributes);
        } catch (InvalidCipherTextException e) {
            //correct, expected exception, nothing to do.
        } catch (InvalidParameterException e) {
            //correct, expected exception, nothing to do.
        } catch (Exception e) {
            System.out.println("Access policy satisfied test failed, " +
                    "attributes = " + Arrays.toString(attributes));
            e.printStackTrace();
            System.exit(1);
        }
    }
    private void try_decentral_invalid_access_policy(Pairing pairing, PairingKeySerParameter publicKey, PairingKeySerParameter masterKey,
                                           final int[][] accessPolicy, final String[] rhos, final String[] attributes) {
        try {
            try_decentral_access_policy(pairing, publicKey, masterKey, accessPolicy, rhos, attributes);
        } catch (InvalidCipherTextException e) {
            //correct, expected exception, nothing to do.
        } catch (InvalidParameterException e) {
            //correct, expected exception, nothing to do.
        } catch (Exception e) {
            System.out.println("Access policy satisfied test failed, " +
                    "attributes = " + Arrays.toString(attributes));
            e.printStackTrace();
            System.exit(1);
        }
    }

    private void try_access_policy(Pairing pairing, PairingKeySerParameter publicKey, PairingKeySerParameter masterKey,
                                   final int[][] accessPolicy, final String[] rhos, final String[] attributes)
            throws InvalidCipherTextException, IOException, ClassNotFoundException {
        //KeyGen and serialization
        PairingKeySerParameter secretKey = engine.keyGen(publicKey, masterKey, attributes);
        byte[] byteArraySecretKey = TestUtils.SerCipherParameter(secretKey);
        CipherParameters anSecretKey = TestUtils.deserCipherParameters(byteArraySecretKey);
        Assert.assertEquals(secretKey, anSecretKey);
        secretKey = (PairingKeySerParameter)anSecretKey;

        //Encryption and serialization
        Element message = pairing.getGT().newRandomElement().getImmutable();
        PairingCipherSerParameter ciphertext = engine.encryption(publicKey, accessPolicy, rhos, message);
        byte[] byteArrayCiphertext = TestUtils.SerCipherParameter(ciphertext);
        CipherParameters anCiphertext = TestUtils.deserCipherParameters(byteArrayCiphertext);
        Assert.assertEquals(ciphertext, anCiphertext);
        ciphertext = (PairingCipherSerParameter)anCiphertext;

        //Decryption
        Element anMessage = engine.decryption(publicKey, secretKey, accessPolicy, rhos, ciphertext);
        Assert.assertEquals(message, anMessage);

        //Encapsulation and serialization
        PairingKeyEncapsulationSerPair encapsulationPair = engine.encapsulation(publicKey, accessPolicy, rhos);
        byte[] sessionKey = encapsulationPair.getSessionKey();
        PairingCipherSerParameter header = encapsulationPair.getHeader();
        byte[] byteArrayHeader = TestUtils.SerCipherParameter(header);
        CipherParameters anHeader = TestUtils.deserCipherParameters(byteArrayHeader);
        Assert.assertEquals(header, anHeader);
        header = (PairingCipherSerParameter)anHeader;

        //Decapsulation
        byte[] anSessionKey = engine.decapsulation(publicKey, secretKey, accessPolicy, rhos, header);
        Assert.assertArrayEquals(sessionKey, anSessionKey);
    }
    private void try_decentral_access_policy(Pairing pairing, PairingKeySerParameter publicKey, PairingKeySerParameter masterKey,
                                   final int[][] accessPolicy, final String[] rhos, final String[] attributes)
            throws InvalidCipherTextException, IOException, ClassNotFoundException {
        //KeyGen and serialization
        PairingKeySerParameter secretKey0 = engine.keyGen(publicKey, masterKey, attributes);
        PairingKeySerParameter secretKey = engine.additionalKeyGen(publicKey, masterKey, attributes, ((CPABERC24SecretKeySerParameter)secretKey0).getSigma());
        byte[] byteArraySecretKey = TestUtils.SerCipherParameter(secretKey);
        CipherParameters anSecretKey = TestUtils.deserCipherParameters(byteArraySecretKey);
        Assert.assertEquals(secretKey, anSecretKey);
        secretKey = (PairingKeySerParameter)anSecretKey;

        //Encryption and serialization
        Element message = pairing.getGT().newRandomElement().getImmutable();
        preCiphertextPack preCiphertextPack = engine.preEncryption(publicKey, accessPolicy, rhos, message);
        PairingCipherSerParameter preCiphertext = preCiphertextPack.preCiphertext;
        PairingCipherSerParameter coCiphertext = engine.coEncryption(publicKey, accessPolicy, rhos, preCiphertext);
        PairingCipherSerParameter ciphertext = engine.finalEncryption(publicKey, accessPolicy, rhos, preCiphertext, coCiphertext, preCiphertextPack.s);
        byte[] byteArrayCiphertext = TestUtils.SerCipherParameter(ciphertext);
        CipherParameters anCiphertext = TestUtils.deserCipherParameters(byteArrayCiphertext);
        Assert.assertEquals(ciphertext, anCiphertext);
        ciphertext = (PairingCipherSerParameter)anCiphertext;

        //Decryption
        //Verify in decrypt
        Element anDecryptCheck = engine.decryptableCheck(publicKey, secretKey, accessPolicy, rhos, ciphertext);
        Assert.assertEquals(pairing.getGT().newOneElement(), anDecryptCheck);
        Element anMessage = engine.decryption(publicKey, secretKey, accessPolicy, rhos, ciphertext);
        Assert.assertEquals(message, anMessage);
        
        //Encapsulation and serialization
        PairingKeyEncapsulationSerPair encapsulationPair = engine.encapsulation(publicKey, accessPolicy, rhos);
        byte[] sessionKey = encapsulationPair.getSessionKey();
        PairingCipherSerParameter header = encapsulationPair.getHeader();
        byte[] byteArrayHeader = TestUtils.SerCipherParameter(header);
        CipherParameters anHeader = TestUtils.deserCipherParameters(byteArrayHeader);
        Assert.assertEquals(header, anHeader);
        header = (PairingCipherSerParameter)anHeader;

        //Decapsulation
        byte[] anSessionKey = engine.decapsulation(publicKey, secretKey, accessPolicy, rhos, header);
        Assert.assertArrayEquals(sessionKey, anSessionKey);
    }

    public void runAllTests(PairingParameters pairingParameters, final String[] attributes)throws Exception {
        try {
            Pairing pairing = PairingFactory.getPairing(pairingParameters);
            // Setup and serialization
            PairingKeySerPair keyPair = engine.setup(pairingParameters, 50, attributes);
            PairingKeySerParameter publicKey = keyPair.getPublic();

            String Jss = publicKey.exportJSONstring();
            PairingKeySerParameter rePublickey = CPABERC24PublicKeySerParameter.importJSONstring(Jss);
            Assert.assertEquals(publicKey, rePublickey);

            byte[] byteArrayPublicKey = TestUtils.SerCipherParameter(publicKey);
            CipherParameters anPublicKey = TestUtils.deserCipherParameters(byteArrayPublicKey);
            Assert.assertEquals(publicKey, anPublicKey);
            publicKey = (PairingKeySerParameter) anPublicKey;

            PairingKeySerParameter masterKey = keyPair.getPrivate();
            byte[] byteArrayMasterKey = TestUtils.SerCipherParameter(masterKey);
            CipherParameters anMasterKey = TestUtils.deserCipherParameters(byteArrayMasterKey);
            Assert.assertEquals(masterKey, anMasterKey);
            masterKey = (PairingKeySerParameter) anMasterKey;

            //test examples
            System.out.println("Test example 1");
            try_valid_access_policy(
                    pairing, publicKey, masterKey,
                    AccessPolicyExamples.access_policy_example_1,
                    AccessPolicyExamples.access_policy_exampe_1_satisfied_1);
            try_valid_access_policy(
                    pairing, publicKey, masterKey,
                    AccessPolicyExamples.access_policy_example_1,
                    AccessPolicyExamples.access_policy_exampe_1_satisfied_2);
            try_invalid_access_policy(
                    pairing, publicKey, masterKey,
                    AccessPolicyExamples.access_policy_example_1,
                    AccessPolicyExamples.access_policy_exampe_1_unsatisfied_1);

            //test example 2
            System.out.println("Test example 2");
            try_valid_access_policy(
                    pairing, publicKey, masterKey,
                    AccessPolicyExamples.access_policy_example_2,
                    AccessPolicyExamples.access_policy_exampe_2_satisfied_1);
            try_valid_access_policy(
                    pairing, publicKey, masterKey,
                    AccessPolicyExamples.access_policy_example_2,
                    AccessPolicyExamples.access_policy_exampe_2_satisfied_2);
            try_invalid_access_policy(
                    pairing, publicKey, masterKey,
                    AccessPolicyExamples.access_policy_example_2,
                    AccessPolicyExamples.access_policy_exampe_2_unsatisfied_1);
            try_invalid_access_policy(
                    pairing, publicKey, masterKey,
                    AccessPolicyExamples.access_policy_example_2,
                    AccessPolicyExamples.access_policy_exampe_2_unsatisfied_2);
            try_invalid_access_policy(
                    pairing, publicKey, masterKey,
                    AccessPolicyExamples.access_policy_example_2,
                    AccessPolicyExamples.access_policy_exampe_2_unsatisfied_3);

            //test example 3
            System.out.println("Test example 3");
            try_valid_access_policy(
                    pairing, publicKey, masterKey,
                    AccessPolicyExamples.access_policy_example_3,
                    AccessPolicyExamples.access_policy_exampe_3_satisfied_1);
            try_invalid_access_policy(
                    pairing, publicKey, masterKey,
                    AccessPolicyExamples.access_policy_example_3,
                    AccessPolicyExamples.access_policy_exampe_3_unsatisfied_1);
            try_invalid_access_policy(
                    pairing, publicKey, masterKey,
                    AccessPolicyExamples.access_policy_example_3,
                    AccessPolicyExamples.access_policy_exampe_3_unsatisfied_2);

            if (engine.isAccessControlEngineSupportThresholdGate()) {
                //test threshold example 1
                System.out.println("Test threshold example 1");
                try_valid_access_policy(
                        pairing, publicKey, masterKey,
                        AccessPolicyExamples.access_policy_threshold_example_1_tree,
                        AccessPolicyExamples.access_policy_threshold_example_1_rho,
                        AccessPolicyExamples.access_policy_threshold_example_1_satisfied01);
                try_valid_access_policy(
                        pairing, publicKey, masterKey,
                        AccessPolicyExamples.access_policy_threshold_example_1_tree,
                        AccessPolicyExamples.access_policy_threshold_example_1_rho,
                        AccessPolicyExamples.access_policy_threshold_example_1_satisfied02);
                try_valid_access_policy(
                        pairing, publicKey, masterKey,
                        AccessPolicyExamples.access_policy_threshold_example_1_tree,
                        AccessPolicyExamples.access_policy_threshold_example_1_rho,
                        AccessPolicyExamples.access_policy_threshold_example_1_satisfied03);
                try_valid_access_policy(
                        pairing, publicKey, masterKey,
                        AccessPolicyExamples.access_policy_threshold_example_1_tree,
                        AccessPolicyExamples.access_policy_threshold_example_1_rho,
                        AccessPolicyExamples.access_policy_threshold_example_1_satisfied04);
                try_valid_access_policy(
                        pairing, publicKey, masterKey,
                        AccessPolicyExamples.access_policy_threshold_example_1_tree,
                        AccessPolicyExamples.access_policy_threshold_example_1_rho,
                        AccessPolicyExamples.access_policy_threshold_example_1_satisfied05);
                try_valid_access_policy(
                        pairing, publicKey, masterKey,
                        AccessPolicyExamples.access_policy_threshold_example_1_tree,
                        AccessPolicyExamples.access_policy_threshold_example_1_rho,
                        AccessPolicyExamples.access_policy_threshold_example_1_satisfied06);
                try_valid_access_policy(
                        pairing, publicKey, masterKey,
                        AccessPolicyExamples.access_policy_threshold_example_1_tree,
                        AccessPolicyExamples.access_policy_threshold_example_1_rho,
                        AccessPolicyExamples.access_policy_threshold_example_1_satisfied07);
                try_valid_access_policy(
                        pairing, publicKey, masterKey,
                        AccessPolicyExamples.access_policy_threshold_example_1_tree,
                        AccessPolicyExamples.access_policy_threshold_example_1_rho,
                        AccessPolicyExamples.access_policy_threshold_example_1_satisfied08);
                try_valid_access_policy(
                        pairing, publicKey, masterKey,
                        AccessPolicyExamples.access_policy_threshold_example_1_tree,
                        AccessPolicyExamples.access_policy_threshold_example_1_rho,
                        AccessPolicyExamples.access_policy_threshold_example_1_satisfied09);
                try_valid_access_policy(
                        pairing, publicKey, masterKey,
                        AccessPolicyExamples.access_policy_threshold_example_1_tree,
                        AccessPolicyExamples.access_policy_threshold_example_1_rho,
                        AccessPolicyExamples.access_policy_threshold_example_1_satisfied10);
                try_valid_access_policy(
                        pairing, publicKey, masterKey,
                        AccessPolicyExamples.access_policy_threshold_example_1_tree,
                        AccessPolicyExamples.access_policy_threshold_example_1_rho,
                        AccessPolicyExamples.access_policy_threshold_example_1_satisfied11);
                try_invalid_access_policy(
                        pairing, publicKey, masterKey,
                        AccessPolicyExamples.access_policy_threshold_example_1_tree,
                        AccessPolicyExamples.access_policy_threshold_example_1_rho,
                        AccessPolicyExamples.access_policy_threshold_example_1_unsatisfied01);
                try_invalid_access_policy(
                        pairing, publicKey, masterKey,
                        AccessPolicyExamples.access_policy_threshold_example_1_tree,
                        AccessPolicyExamples.access_policy_threshold_example_1_rho,
                        AccessPolicyExamples.access_policy_threshold_example_1_unsatisfied02);
                try_invalid_access_policy(
                        pairing, publicKey, masterKey,
                        AccessPolicyExamples.access_policy_threshold_example_1_tree,
                        AccessPolicyExamples.access_policy_threshold_example_1_rho,
                        AccessPolicyExamples.access_policy_threshold_example_1_unsatisfied03);
                try_invalid_access_policy(
                        pairing, publicKey, masterKey,
                        AccessPolicyExamples.access_policy_threshold_example_1_tree,
                        AccessPolicyExamples.access_policy_threshold_example_1_rho,
                        AccessPolicyExamples.access_policy_threshold_example_1_unsatisfied04);
                try_invalid_access_policy(
                        pairing, publicKey, masterKey,
                        AccessPolicyExamples.access_policy_threshold_example_1_tree,
                        AccessPolicyExamples.access_policy_threshold_example_1_rho,
                        AccessPolicyExamples.access_policy_threshold_example_1_unsatisfied05);
                try_invalid_access_policy(
                        pairing, publicKey, masterKey,
                        AccessPolicyExamples.access_policy_threshold_example_1_tree,
                        AccessPolicyExamples.access_policy_threshold_example_1_rho,
                        AccessPolicyExamples.access_policy_threshold_example_1_unsatisfied06);
                try_invalid_access_policy(
                        pairing, publicKey, masterKey,
                        AccessPolicyExamples.access_policy_threshold_example_1_tree,
                        AccessPolicyExamples.access_policy_threshold_example_1_rho,
                        AccessPolicyExamples.access_policy_threshold_example_1_unsatisfied07);
                try_invalid_access_policy(
                        pairing, publicKey, masterKey,
                        AccessPolicyExamples.access_policy_threshold_example_1_tree,
                        AccessPolicyExamples.access_policy_threshold_example_1_rho,
                        AccessPolicyExamples.access_policy_threshold_example_1_unsatisfied08);
                try_invalid_access_policy(
                        pairing, publicKey, masterKey,
                        AccessPolicyExamples.access_policy_threshold_example_1_tree,
                        AccessPolicyExamples.access_policy_threshold_example_1_rho,
                        AccessPolicyExamples.access_policy_threshold_example_1_unsatisfied09);

                //test threshold example 2
                System.out.println("Test threshold example 2");
                try_valid_access_policy(
                        pairing, publicKey, masterKey,
                        AccessPolicyExamples.access_policy_threshold_example_2_tree,
                        AccessPolicyExamples.access_policy_threshold_example_2_rho,
                        AccessPolicyExamples.access_policy_threshold_example_2_satisfied01);
                try_invalid_access_policy(
                        pairing, publicKey, masterKey,
                        AccessPolicyExamples.access_policy_threshold_example_2_tree,
                        AccessPolicyExamples.access_policy_threshold_example_2_rho,
                        AccessPolicyExamples.access_policy_threshold_example_2_unsatisfied01);
                try_invalid_access_policy(
                        pairing, publicKey, masterKey,
                        AccessPolicyExamples.access_policy_threshold_example_2_tree,
                        AccessPolicyExamples.access_policy_threshold_example_2_rho,
                        AccessPolicyExamples.access_policy_threshold_example_2_unsatisfied02);
            }
            System.out.println(engine.getEngineName() + " test passed");
        } catch (ClassNotFoundException e) {
            System.out.println("setup test failed.");
            e.printStackTrace();
            System.exit(1);
        } catch (IOException e) {
            System.out.println("setup test failed.");
            e.printStackTrace();
            System.exit(1);
        }
    }

    public void runAllDecentralTests(PairingParameters pairingParameters, final String[] attributes) {
        try {
            Pairing pairing = PairingFactory.getPairing(pairingParameters);
            // Setup and serialization
            PairingKeySerPair keyPair = engine.decentralSetup(pairingParameters, 50, attributes, CPABERC24KeyPairGenerator.generateHashAID("GN-002",pairing));
            PairingKeySerParameter publicKey = keyPair.getPublic();
            byte[] byteArrayPublicKey = TestUtils.SerCipherParameter(publicKey);
            CipherParameters anPublicKey = TestUtils.deserCipherParameters(byteArrayPublicKey);
            Assert.assertEquals(publicKey, anPublicKey);
            publicKey = (PairingKeySerParameter) anPublicKey;

            PairingKeySerParameter masterKey = keyPair.getPrivate();
            byte[] byteArrayMasterKey = TestUtils.SerCipherParameter(masterKey);
            CipherParameters anMasterKey = TestUtils.deserCipherParameters(byteArrayMasterKey);
            Assert.assertEquals(masterKey, anMasterKey);
            masterKey = (PairingKeySerParameter) anMasterKey;

            //test examples
            System.out.println("Test example 1");
            try_decentral_valid_access_policy(
                    pairing, publicKey, masterKey,
                    AccessPolicyExamples.access_policy_example_1,
                    AccessPolicyExamples.access_policy_exampe_1_satisfied_1);
            try_decentral_valid_access_policy(
                    pairing, publicKey, masterKey,
                    AccessPolicyExamples.access_policy_example_1,
                    AccessPolicyExamples.access_policy_exampe_1_satisfied_2);
            try_decentral_invalid_access_policy(
                    pairing, publicKey, masterKey,
                    AccessPolicyExamples.access_policy_example_1,
                    AccessPolicyExamples.access_policy_exampe_1_unsatisfied_1);

            //test example 2
            System.out.println("Test example 2");
            try_decentral_valid_access_policy(
                    pairing, publicKey, masterKey,
                    AccessPolicyExamples.access_policy_example_2,
                    AccessPolicyExamples.access_policy_exampe_2_satisfied_1);
            try_decentral_valid_access_policy(
                    pairing, publicKey, masterKey,
                    AccessPolicyExamples.access_policy_example_2,
                    AccessPolicyExamples.access_policy_exampe_2_satisfied_2);
            try_decentral_invalid_access_policy(
                    pairing, publicKey, masterKey,
                    AccessPolicyExamples.access_policy_example_2,
                    AccessPolicyExamples.access_policy_exampe_2_unsatisfied_1);
            try_decentral_invalid_access_policy(
                    pairing, publicKey, masterKey,
                    AccessPolicyExamples.access_policy_example_2,
                    AccessPolicyExamples.access_policy_exampe_2_unsatisfied_2);
            try_decentral_invalid_access_policy(
                    pairing, publicKey, masterKey,
                    AccessPolicyExamples.access_policy_example_2,
                    AccessPolicyExamples.access_policy_exampe_2_unsatisfied_3);

            //test example 3
            System.out.println("Test example 3");
            try_decentral_valid_access_policy(
                    pairing, publicKey, masterKey,
                    AccessPolicyExamples.access_policy_example_3,
                    AccessPolicyExamples.access_policy_exampe_3_satisfied_1);
            try_decentral_invalid_access_policy(
                    pairing, publicKey, masterKey,
                    AccessPolicyExamples.access_policy_example_3,
                    AccessPolicyExamples.access_policy_exampe_3_unsatisfied_1);
           try_decentral_invalid_access_policy(
                    pairing, publicKey, masterKey,
                    AccessPolicyExamples.access_policy_example_3,
                    AccessPolicyExamples.access_policy_exampe_3_unsatisfied_2);

            if (engine.isAccessControlEngineSupportThresholdGate()) {
                //test threshold example 1
                System.out.println("Test threshold example 1");
                try_decentral_valid_access_policy(
                        pairing, publicKey, masterKey,
                        AccessPolicyExamples.access_policy_threshold_example_1_tree,
                        AccessPolicyExamples.access_policy_threshold_example_1_rho,
                        AccessPolicyExamples.access_policy_threshold_example_1_satisfied01);
                try_decentral_valid_access_policy(
                        pairing, publicKey, masterKey,
                        AccessPolicyExamples.access_policy_threshold_example_1_tree,
                        AccessPolicyExamples.access_policy_threshold_example_1_rho,
                        AccessPolicyExamples.access_policy_threshold_example_1_satisfied02);
                try_decentral_valid_access_policy(
                        pairing, publicKey, masterKey,
                        AccessPolicyExamples.access_policy_threshold_example_1_tree,
                        AccessPolicyExamples.access_policy_threshold_example_1_rho,
                        AccessPolicyExamples.access_policy_threshold_example_1_satisfied03);
                try_decentral_valid_access_policy(
                        pairing, publicKey, masterKey,
                        AccessPolicyExamples.access_policy_threshold_example_1_tree,
                        AccessPolicyExamples.access_policy_threshold_example_1_rho,
                        AccessPolicyExamples.access_policy_threshold_example_1_satisfied04);
                try_decentral_valid_access_policy(
                        pairing, publicKey, masterKey,
                        AccessPolicyExamples.access_policy_threshold_example_1_tree,
                        AccessPolicyExamples.access_policy_threshold_example_1_rho,
                        AccessPolicyExamples.access_policy_threshold_example_1_satisfied05);
                try_decentral_valid_access_policy(
                        pairing, publicKey, masterKey,
                        AccessPolicyExamples.access_policy_threshold_example_1_tree,
                        AccessPolicyExamples.access_policy_threshold_example_1_rho,
                        AccessPolicyExamples.access_policy_threshold_example_1_satisfied06);
                try_decentral_valid_access_policy(
                        pairing, publicKey, masterKey,
                        AccessPolicyExamples.access_policy_threshold_example_1_tree,
                        AccessPolicyExamples.access_policy_threshold_example_1_rho,
                        AccessPolicyExamples.access_policy_threshold_example_1_satisfied07);
                try_decentral_valid_access_policy(
                        pairing, publicKey, masterKey,
                        AccessPolicyExamples.access_policy_threshold_example_1_tree,
                        AccessPolicyExamples.access_policy_threshold_example_1_rho,
                        AccessPolicyExamples.access_policy_threshold_example_1_satisfied08);
                try_decentral_valid_access_policy(
                        pairing, publicKey, masterKey,
                        AccessPolicyExamples.access_policy_threshold_example_1_tree,
                        AccessPolicyExamples.access_policy_threshold_example_1_rho,
                        AccessPolicyExamples.access_policy_threshold_example_1_satisfied09);
                try_decentral_valid_access_policy(
                        pairing, publicKey, masterKey,
                        AccessPolicyExamples.access_policy_threshold_example_1_tree,
                        AccessPolicyExamples.access_policy_threshold_example_1_rho,
                        AccessPolicyExamples.access_policy_threshold_example_1_satisfied10);
                try_decentral_valid_access_policy(
                        pairing, publicKey, masterKey,
                        AccessPolicyExamples.access_policy_threshold_example_1_tree,
                        AccessPolicyExamples.access_policy_threshold_example_1_rho,
                        AccessPolicyExamples.access_policy_threshold_example_1_satisfied11);
                try_decentral_invalid_access_policy(
                        pairing, publicKey, masterKey,
                        AccessPolicyExamples.access_policy_threshold_example_1_tree,
                        AccessPolicyExamples.access_policy_threshold_example_1_rho,
                        AccessPolicyExamples.access_policy_threshold_example_1_unsatisfied01);
                try_decentral_invalid_access_policy(
                        pairing, publicKey, masterKey,
                        AccessPolicyExamples.access_policy_threshold_example_1_tree,
                        AccessPolicyExamples.access_policy_threshold_example_1_rho,
                        AccessPolicyExamples.access_policy_threshold_example_1_unsatisfied02);
                try_decentral_invalid_access_policy(
                        pairing, publicKey, masterKey,
                        AccessPolicyExamples.access_policy_threshold_example_1_tree,
                        AccessPolicyExamples.access_policy_threshold_example_1_rho,
                        AccessPolicyExamples.access_policy_threshold_example_1_unsatisfied03);
                try_decentral_invalid_access_policy(
                        pairing, publicKey, masterKey,
                        AccessPolicyExamples.access_policy_threshold_example_1_tree,
                        AccessPolicyExamples.access_policy_threshold_example_1_rho,
                        AccessPolicyExamples.access_policy_threshold_example_1_unsatisfied04);
                try_decentral_invalid_access_policy(
                        pairing, publicKey, masterKey,
                        AccessPolicyExamples.access_policy_threshold_example_1_tree,
                        AccessPolicyExamples.access_policy_threshold_example_1_rho,
                        AccessPolicyExamples.access_policy_threshold_example_1_unsatisfied05);
                try_decentral_invalid_access_policy(
                        pairing, publicKey, masterKey,
                        AccessPolicyExamples.access_policy_threshold_example_1_tree,
                        AccessPolicyExamples.access_policy_threshold_example_1_rho,
                        AccessPolicyExamples.access_policy_threshold_example_1_unsatisfied06);
                try_decentral_invalid_access_policy(
                        pairing, publicKey, masterKey,
                        AccessPolicyExamples.access_policy_threshold_example_1_tree,
                        AccessPolicyExamples.access_policy_threshold_example_1_rho,
                        AccessPolicyExamples.access_policy_threshold_example_1_unsatisfied07);
                try_decentral_invalid_access_policy(
                        pairing, publicKey, masterKey,
                        AccessPolicyExamples.access_policy_threshold_example_1_tree,
                        AccessPolicyExamples.access_policy_threshold_example_1_rho,
                        AccessPolicyExamples.access_policy_threshold_example_1_unsatisfied08);
                try_decentral_invalid_access_policy(
                        pairing, publicKey, masterKey,
                        AccessPolicyExamples.access_policy_threshold_example_1_tree,
                        AccessPolicyExamples.access_policy_threshold_example_1_rho,
                        AccessPolicyExamples.access_policy_threshold_example_1_unsatisfied09);

                //test threshold example 2
                System.out.println("Test threshold example 2");
                try_decentral_valid_access_policy(
                        pairing, publicKey, masterKey,
                        AccessPolicyExamples.access_policy_threshold_example_2_tree,
                        AccessPolicyExamples.access_policy_threshold_example_2_rho,
                        AccessPolicyExamples.access_policy_threshold_example_2_satisfied01);
                try_decentral_invalid_access_policy(
                        pairing, publicKey, masterKey,
                        AccessPolicyExamples.access_policy_threshold_example_2_tree,
                        AccessPolicyExamples.access_policy_threshold_example_2_rho,
                        AccessPolicyExamples.access_policy_threshold_example_2_unsatisfied01);
                try_decentral_invalid_access_policy(
                        pairing, publicKey, masterKey,
                        AccessPolicyExamples.access_policy_threshold_example_2_tree,
                        AccessPolicyExamples.access_policy_threshold_example_2_rho,
                        AccessPolicyExamples.access_policy_threshold_example_2_unsatisfied02);
            }
            System.out.println(engine.getEngineName() + " test passed");
        } catch (ClassNotFoundException e) {
            System.out.println("setup test failed.");
            e.printStackTrace();
            System.exit(1);
        } catch (IOException e) {
            System.out.println("setup test failed.");
            e.printStackTrace();
            System.exit(1);
        }
    }
    public void testCPABERC24Engine() throws Exception{
        this.engine = CPABERC24Engine.getInstance();
        System.out.println("Test " + engine.getEngineName() + " using " + AccessTreeEngine.SCHEME_NAME);
        engine.setAccessControlEngine(AccessTreeEngine.getInstance());
        runAllTests(PairingFactory.getPairingParameters(TestUtils.TEST_PAIRING_PARAMETERS_PATH_a_80_256),AccessGlobalSetExamples.access_global_set_exampe_1);
        runAllDecentralTests(PairingFactory.getPairingParameters(TestUtils.TEST_PAIRING_PARAMETERS_PATH_a_80_256),AccessGlobalSetExamples.access_global_set_exampe_1);
        System.out.println("Test " + engine.getEngineName() + " using " + LSSSLW10Engine.SCHEME_NAME);
        engine.setAccessControlEngine(LSSSLW10Engine.getInstance());
        runAllTests(PairingFactory.getPairingParameters(TestUtils.TEST_PAIRING_PARAMETERS_PATH_a_80_256),AccessGlobalSetExamples.access_global_set_exampe_1);
        runAllDecentralTests(PairingFactory.getPairingParameters(TestUtils.TEST_PAIRING_PARAMETERS_PATH_a_80_256),AccessGlobalSetExamples.access_global_set_exampe_1);
    }
}

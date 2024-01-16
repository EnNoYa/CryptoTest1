package com.example;
import cn.edu.buaa.crypto.utils.PairingUtils;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

public class JPBCtest {
    public static void main(String[] args) {
        // 初始化JPBC Pairing
        PairingParameters pairingParameters = PairingFactory.getPairingParameters(PairingUtils.PATH_a_160_512);
        Pairing pairing =  PairingFactory.getPairing(pairingParameters);

        // 測量 paring 函數的執行時間
        Element g = pairing.getG1().newRandomElement().getImmutable();
        Element z = pairing.getZr().newRandomElement().getImmutable();
        long startTimeParing = System.currentTimeMillis();
        for(int i=0; i<20; ++i){
        Element resultParing = pairing.pairing(g, g);
        }
        long endTimeParing = System.currentTimeMillis();
        long elapsedTimeParing = endTimeParing - startTimeParing;

        long startITimeParing = System.currentTimeMillis();
        for(int i=0; i<20; ++i){
        Element resultIParing = pairing.pairing(g, g).getImmutable();
        }
        long endITimeParing = System.currentTimeMillis();
        long elapsedITimeParing = endITimeParing - startITimeParing;
        // 測量 powzn 函數的執行時間
        long startTimePowzn = System.currentTimeMillis();
        for(int i=0; i<20; ++i){
        Element resultPowzn = g.powZn(z);
        }
        long endTimePowzn = System.currentTimeMillis();
        long elapsedTimePowzn = endTimePowzn - startTimePowzn;

        long startITimePowzn = System.currentTimeMillis();
        for(int i=0; i<20; ++i){
        Element resultIPowzn = g.powZn(z).getImmutable();
        }
        long endITimePowzn = System.currentTimeMillis();
        long elapsedITimePowzn = endITimePowzn - startITimePowzn;
        // 打印結果
        System.out.println("Paring 函數執行時間: " + elapsedTimeParing + " 毫秒");
        System.out.println("Powzn 函數執行時間: " + elapsedTimePowzn + " 毫秒");
        System.out.println("Immutable Paring 函數執行時間: " + elapsedITimeParing + " 毫秒");
        System.out.println("Immutable Powzn 函數執行時間: " + elapsedITimePowzn + " 毫秒");
    }
}

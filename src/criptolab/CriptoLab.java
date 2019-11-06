/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package criptolab;

import java.util.Arrays;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.InvalidCipherTextException;

/**
 *
 * @author Alber
 */
public class CriptoLab {

    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) {
        // Generación de llaves
        KeyGenerator kg = new KeyGenerator();
        AsymmetricCipherKeyPair keyPair = kg.generateKeyPair();
        PublicKeyParameters publicKey = (PublicKeyParameters) keyPair.getPublic();
        PrivateKeyParameters privKey = (PrivateKeyParameters) keyPair.getPrivate();

        byte[] plainMessage = new byte[187];
        //System.out.println("Plain Message: " + Arrays.toString(plainMessage));
        //Cifrado
        Cipher cipher = new Cipher();
        cipher.init(true, publicKey);
        byte[] cipherMessage = cipher.messageEncrypt(plainMessage);
        //System.out.println("Cipher Message: " + Arrays.toString(cipherMessage));

        //Decifrado
        try {
            cipher.init(false, privKey);
            byte[] decodedMessage = cipher.messageDecrypt(cipherMessage);
            if (decodedMessage.equals(plainMessage)) {
                System.out.println("Exito");
            }else{
                System.out.println("Yaper");
            }
        } catch (InvalidCipherTextException ex) {
            ex.printStackTrace();
        }
    }

}

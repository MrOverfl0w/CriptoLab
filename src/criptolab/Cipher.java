/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package criptolab;

import java.security.SecureRandom;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.pqc.crypto.MessageEncryptor;
import org.bouncycastle.pqc.crypto.mceliece.McElieceKeyParameters;
import org.bouncycastle.pqc.crypto.mceliece.McEliecePrivateKeyParameters;
import org.bouncycastle.pqc.crypto.mceliece.McEliecePublicKeyParameters;
import org.bouncycastle.pqc.math.linearalgebra.GF2Matrix;
import org.bouncycastle.pqc.math.linearalgebra.GF2Vector;
import org.bouncycastle.pqc.math.linearalgebra.GF2mField;
import org.bouncycastle.pqc.math.linearalgebra.GoppaCode;
import org.bouncycastle.pqc.math.linearalgebra.Permutation;
import org.bouncycastle.pqc.math.linearalgebra.PolynomialGF2mSmallM;
import org.bouncycastle.pqc.math.linearalgebra.Vector;

/**
 *
 * @author Alber
 */
public class Cipher implements MessageEncryptor{


    // the source of randomness
    private SecureRandom sr;

    // the McEliece main parameters
    private int n, k, t;

    // The maximum number of bytes the cipher can decrypt
    public int maxPlainTextSize;

    // The maximum number of bytes the cipher can encrypt
    public int cipherTextSize;

    private PublicKeyParameters publicKey;
    private PrivateKeyParameters privKey;
    private boolean forEncryption;


    public void init(boolean forEncryption, CipherParameters param){
        this.forEncryption = forEncryption;
        if (forEncryption){
            if (param instanceof ParametersWithRandom)
            {
                ParametersWithRandom rParam = (ParametersWithRandom)param;

                this.sr = rParam.getRandom();
                this.publicKey = (PublicKeyParameters)rParam.getParameters();
                this.initCipherEncrypt(publicKey);

            }
            else
            {
                this.sr = CryptoServicesRegistrar.getSecureRandom();
                this.publicKey = (PublicKeyParameters)param;
                this.initCipherEncrypt(publicKey);
            }
        }else{
            if (param instanceof ParametersWithRandom)
            {
                ParametersWithRandom rParam = (ParametersWithRandom)param;

                this.sr = rParam.getRandom();
                this.privKey = (PrivateKeyParameters)rParam.getParameters();
                this.initCipherDecrypt(privKey);

            }
            else
            {
                this.sr = CryptoServicesRegistrar.getSecureRandom();
                this.privKey = (PrivateKeyParameters)param;
                this.initCipherDecrypt(privKey);
            }
        }

    }

    /**
     * Return the publicKey size of the given publicKey object.
     *
     * @param key the McElieceKeyParameters object
     * @return the keysize of the given publicKey object
     */

    public int getKeySize(McElieceKeyParameters key)
    {

        if (key instanceof PublicKeyParameters)
        {
            return ((PublicKeyParameters)key).getN();

        }
        if (key instanceof PrivateKeyParameters)
        {
            return ((PrivateKeyParameters)key).getN();
        }
        throw new IllegalArgumentException("unsupported type");

    }


    private void initCipherEncrypt(PublicKeyParameters pubKey)
    {
        this.sr = sr != null ? sr : CryptoServicesRegistrar.getSecureRandom();
        n = pubKey.getN();
        k = pubKey.getK();
        t = pubKey.getT();
        cipherTextSize = n >> 3;
        maxPlainTextSize = (k >> 3);
    }
    
    private void initCipherDecrypt(PrivateKeyParameters privKey)
    {
        n = privKey.getN();
        k = privKey.getK();

        maxPlainTextSize = (k >> 3);
        cipherTextSize = n >> 3;
    }


    /**
     * Encrypt a plain text.
     *
     * @param input the plain text
     * @return the cipher text
     */
    @Override
    public byte[] messageEncrypt(byte[] input)
    {
        GF2Vector m = computeMessageRepresentative(input);
        GF2Vector z = new GF2Vector(n, t, sr);

        GF2Matrix g = publicKey.getG();
        //Multiplicar m y G
        Vector mG = g.leftMultiply(m);
        //Sumar vector
        GF2Vector mGZ = (GF2Vector)mG.add(z);

        return mGZ.getEncoded();
    }

    //Mensaje representado como un vector sobre el campo
    private GF2Vector computeMessageRepresentative(byte[] input){
        byte[] data = new byte[maxPlainTextSize + ((k & 0x07) != 0 ? 1 : 0)];
        System.arraycopy(input, 0, data, 0, input.length);
        data[input.length] = 0x01;
        return GF2Vector.OS2VP(k, data);
    }

    @Override
    public byte[] messageDecrypt(byte[] input) throws InvalidCipherTextException {
        GF2Vector vec = GF2Vector.OS2VP(n, input);
        GF2mField field = privKey.getField();
        PolynomialGF2mSmallM gp = privKey.getGoppaPoly();
        GF2Matrix sInv = privKey.getSInv();
        Permutation p = privKey.getP();
        Permutation lpm = privKey.getLpm();
        GF2Matrix h = privKey.getH();
        PolynomialGF2mSmallM[] qInv = privKey.getQInv();

        // P = p * lpm
        Permutation P = lpm.rightMultiply(p);
        
        // compute P^-1
        Permutation pInv = P.computeInverse();

        // compute c P^-1
        GF2Vector cPInv = (GF2Vector)vec.multiply(pInv);

        // compute syndrome of c P^-1
        GF2Vector syndrome = (GF2Vector)h.rightMultiply(cPInv);

        // decode syndrome
        GF2Vector z = GoppaCode.syndromeDecode(syndrome, field, gp, qInv);
        GF2Vector mSG = (GF2Vector)cPInv.add(z);

        // multiply codeword with P1 and error vector with P
        mSG = (GF2Vector)mSG.multiply(lpm);

        // extract mS (last k columns of mSG)
        GF2Vector mS = mSG.extractRightVector(k);

        // compute plaintext vector
        GF2Vector mVec = (GF2Vector)sInv.leftMultiply(mS);

        // compute and return plaintext
        return computeMessage(mVec);
    }

    private byte[] computeMessage(GF2Vector mr) throws InvalidCipherTextException{
        byte[] mrBytes = mr.getEncoded();
        // find first non-zero byte
        int index;
        for (index = mrBytes.length - 1; index >= 0 && mrBytes[index] == 0; index--)
        {
            ;
        }

        // check if padding byte is valid
        if (index<0 || mrBytes[index] != 0x01)
        {
            throw new InvalidCipherTextException("Bad Padding: invalid ciphertext");
        }

        // extract and return message
        byte[] mBytes = new byte[index];
        System.arraycopy(mrBytes, 0, mBytes, 0, index);
        return mBytes;
    }
    
}

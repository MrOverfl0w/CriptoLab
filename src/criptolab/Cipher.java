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
    private boolean forEncryption;


    public void init(boolean forEncryption,
                     CipherParameters param)
    {
        this.forEncryption = forEncryption;
        if (forEncryption)
        {
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

        if (key instanceof McEliecePublicKeyParameters)
        {
            return ((PublicKeyParameters)key).getN();

        }
        if (key instanceof McEliecePrivateKeyParameters)
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
        Vector mG = g.leftMultiply(m);
        GF2Vector mGZ = (GF2Vector)mG.add(z);

        return mGZ.getEncoded();
    }

    private GF2Vector computeMessageRepresentative(byte[] input)
    {
        byte[] data = new byte[maxPlainTextSize + ((k & 0x07) != 0 ? 1 : 0)];
        System.arraycopy(input, 0, data, 0, input.length);
        data[input.length] = 0x01;
        return GF2Vector.OS2VP(k, data);
    }

    @Override
    public byte[] messageDecrypt(byte[] cipher) throws InvalidCipherTextException {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

    
}

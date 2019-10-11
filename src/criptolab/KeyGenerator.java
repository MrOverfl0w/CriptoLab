/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package criptolab;

import java.security.SecureRandom;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.AsymmetricCipherKeyPairGenerator;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.KeyGenerationParameters;
import org.bouncycastle.pqc.crypto.mceliece.McElieceKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.mceliece.McElieceParameters;
import org.bouncycastle.pqc.crypto.mceliece.McEliecePrivateKeyParameters;
import org.bouncycastle.pqc.crypto.mceliece.McEliecePublicKeyParameters;
import org.bouncycastle.pqc.math.linearalgebra.GF2Matrix;
import org.bouncycastle.pqc.math.linearalgebra.GF2mField;
import org.bouncycastle.pqc.math.linearalgebra.GoppaCode;
import org.bouncycastle.pqc.math.linearalgebra.Permutation;
import org.bouncycastle.pqc.math.linearalgebra.PolynomialGF2mSmallM;
import org.bouncycastle.pqc.math.linearalgebra.PolynomialRingGF2m;

/**
 *
 * @author Alber
 */
public class KeyGenerator implements AsymmetricCipherKeyPairGenerator{
    
    /**
     * The OID of the algorithm.
     */
    private static final String OID = "1.3.6.1.4.1.8301.3.1.3.4.1";

    private McElieceKeyGenerationParameters mcElieceParams;

    // the extension degree of the finite field GF(2^m)
    private int m;

    // the length of the code
    private int n;

    // the error correction capability
    private int t;

    // the field polynomial
    private int fieldPoly;

    // the source of randomness
    private SecureRandom random;

    // flag indicating whether the key pair generator has been initialized
    private boolean initialized = false;


    /**
     * Default initialization of the key pair generator.
     */
    private void initializeDefault()
    {
        McElieceKeyGenerationParameters mcParams = new McElieceKeyGenerationParameters(CryptoServicesRegistrar.getSecureRandom(), new McElieceParameters());
        initialize(mcParams);
    }

    private void initialize(KeyGenerationParameters param)
    {
        this.mcElieceParams = (McElieceKeyGenerationParameters)param;

        // set source of randomness
        this.random = param.getRandom();
        if (this.random == null)
        {
            this.random = CryptoServicesRegistrar.getSecureRandom();
        }

        this.m = this.mcElieceParams.getParameters().getM();
        this.n = this.mcElieceParams.getParameters().getN();
        this.t = this.mcElieceParams.getParameters().getT();
        this.fieldPoly = this.mcElieceParams.getParameters().getFieldPoly();
        this.initialized = true;
    }


    private AsymmetricCipherKeyPair genKeyPair()
    {

        if (!initialized)
        {
            initializeDefault();
        }

        // Se define el campo GF(2^m)
        GF2mField field = new GF2mField(m, fieldPoly);

        // Se genera un polinomio irreducible sobre el campo (polinomio de Goppa)
        PolynomialGF2mSmallM gp = new PolynomialGF2mSmallM(field, t,
            PolynomialGF2mSmallM.RANDOM_IRREDUCIBLE_POLYNOMIAL, random);

        // Se obtiene la matriz de control del código de Goppa
        GF2Matrix h = createCanonicalCheckMatrix(field, gp);

        // compute short systematic form of check matrix
        GoppaCode.MaMaPe mmp = GoppaCode.computeSystematicForm(h, random);
        GF2Matrix shortH = mmp.getSecondMatrix();

        // compute short systematic form of generator matrix
        GF2Matrix shortG = (GF2Matrix)shortH.computeTranspose();

        // extend to full systematic form
        GF2Matrix gPrime = shortG.extendLeftCompactForm();

        // obtain number of rows of G' (= dimension of the code)
        int k = shortG.getNumRows();

        // generate random invertible (k x k)-matrix S and its inverse S^-1
        GF2Matrix[] S = GF2Matrix
            .createRandomRegularMatrixAndItsInverse(k, random);

        // generate random permutation P
        Permutation P = new Permutation(n, random);

        // compute public matrix G=S*G'*P
        GF2Matrix G = (GF2Matrix) S[0].rightMultiply(gPrime);
        G = (GF2Matrix)G.rightMultiply(P);


        // generate keys
        PublicKeyParameters pubKey = new PublicKeyParameters(n, t, G);
        PrivateKeyParameters privKey = new PrivateKeyParameters(n, k, field, gp, P, S[1]);

        // return key pair
        return new AsymmetricCipherKeyPair(pubKey, privKey);
    }

    @Override
    public void init(KeyGenerationParameters param)
    {
        this.initialize(param);
    }

    @Override
    public AsymmetricCipherKeyPair generateKeyPair()
    {
        return genKeyPair();
    }
    
    
    
    
    /**
     * Construct the check matrix of a Goppa code in canonical form from the
     * irreducible Goppa polynomial over the finite field
     * <tt>GF(2<sup>m</sup>)</tt>.
     *
     * @param field the finite field
     * @param gp    the irreducible Goppa polynomial
     */
    public static GF2Matrix createCanonicalCheckMatrix(GF2mField field,
                                                       PolynomialGF2mSmallM gp)
    {
        int m = field.getDegree();
        int n = 1 << m;
        int t = gp.getDegree();

        /* create matrix H over GF(2^m) */

        int[][] hArray = new int[t][n];

        // create matrix YZ
        int[][] yz = new int[t][n];
        for (int j = 0; j < n; j++)
        {
            // here j is used as index and as element of field GF(2^m)
            yz[0][j] = field.inverse(gp.evaluateAt(j));
        }

        for (int i = 1; i < t; i++)
        {
            for (int j = 0; j < n; j++)
            {
                // here j is used as index and as element of field GF(2^m)
                yz[i][j] = field.mult(yz[i - 1][j], j);
            }
        }

        // create matrix H = XYZ
        for (int i = 0; i < t; i++)
        {
            for (int j = 0; j < n; j++)
            {
                for (int k = 0; k <= i; k++)
                {
                    hArray[i][j] = field.add(hArray[i][j], field.mult(yz[k][j],
                        gp.getCoefficient(t + k - i)));
                }
            }
        }

        /* convert to matrix over GF(2) */

        int[][] result = new int[t * m][(n + 31) >>> 5];

        for (int j = 0; j < n; j++)
        {
            int q = j >>> 5;
            int r = 1 << (j & 0x1f);
            for (int i = 0; i < t; i++)
            {
                int e = hArray[i][j];
                for (int u = 0; u < m; u++)
                {
                    int b = (e >>> u) & 1;
                    if (b != 0)
                    {
                        int ind = (i + 1) * m - u - 1;
                        result[ind][q] ^= r;
                    }
                }
            }
        }

        return new GF2Matrix(n, result);
    }
    
}
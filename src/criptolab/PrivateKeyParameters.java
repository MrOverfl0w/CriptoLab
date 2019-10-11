/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package criptolab;

import org.bouncycastle.pqc.crypto.mceliece.McElieceKeyParameters;
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
public class PrivateKeyParameters extends McElieceKeyParameters{

    // the length of the code
    private int n;

    // the dimension of the code, where <tt>k &gt;= n - mt</tt>
    private int k;

    // the underlying finite field
    private GF2mField field;

    // the irreducible Goppa polynomial
    private PolynomialGF2mSmallM goppaPoly;

    // a k x k random binary non-singular matrix
    private GF2Matrix sInv;

    // the permutation used to compute the public generator matrix
    private Permutation P;

    // the canonical check matrix of the code
    private GF2Matrix h;

    // the matrix used to compute square roots in <tt>(GF(2^m))^t</tt>
    private PolynomialGF2mSmallM[] qInv;
    
    
    
    public PrivateKeyParameters(int n, int k, GF2mField field,
                                        PolynomialGF2mSmallM gp, Permutation P, GF2Matrix sInv)
    {
        super(true, null);
        this.k = k;
        this.n = n;
        this.field = field;
        this.goppaPoly = gp;
        this.sInv = sInv;
        this.P = P;
        this.h = GoppaCode.createCanonicalCheckMatrix(field, gp);

        PolynomialRingGF2m ring = new PolynomialRingGF2m(field, gp);

          // matrix used to compute square roots in (GF(2^m))^t
        this.qInv = ring.getSquareRootMatrix();
    }
    
}

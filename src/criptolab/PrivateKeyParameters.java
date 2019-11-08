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
    
    // the permutation used to compute the systematic form of the matrix
    private Permutation lpm;

    // the canonical check matrix of the code
    private GF2Matrix h;

    // the matrix used to compute square roots in <tt>(GF(2^m))^t</tt>
    private PolynomialGF2mSmallM[] qInv;
    
    
    
    public PrivateKeyParameters(int n, int k, GF2mField field,
                                        PolynomialGF2mSmallM gp, Permutation P, Permutation lpm, GF2Matrix sInv, GF2Matrix h)
    {
        super(true, null);
        this.k = k;
        this.n = n;
        this.field = field;
        this.goppaPoly = gp;
        this.sInv = sInv;
        this.P = P;
        this.lpm = lpm;
        this.h = h;

        PolynomialRingGF2m ring = new PolynomialRingGF2m(field, gp);

          // matrix used to compute square roots in (GF(2^m))^t
        this.qInv = ring.getSquareRootMatrix();
    }

    int getN() {
        return n;
    }

    public int getK() {
        return k;
    }

    public GF2mField getField() {
        return field;
    }

    public PolynomialGF2mSmallM getGoppaPoly() {
        return goppaPoly;
    }

    public GF2Matrix getSInv() {
        return sInv;
    }

    public Permutation getP() {
        return P;
    }

    public GF2Matrix getH() {
        return h;
    }

    public PolynomialGF2mSmallM[] getQInv() {
        return qInv;
    }

    public Permutation getLpm() {
        return lpm;
    }
    
}

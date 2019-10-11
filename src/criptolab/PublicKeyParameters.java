/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package criptolab;

import org.bouncycastle.pqc.crypto.mceliece.McElieceKeyParameters;
import org.bouncycastle.pqc.math.linearalgebra.GF2Matrix;

/**
 *
 * @author Alber
 */
public class PublicKeyParameters extends McElieceKeyParameters{
    
    // the length of the code
    private int n;

    // the error correction capability of the code
    private int t;

    // the generator matrix
    private GF2Matrix g;
    
    public PublicKeyParameters(int n, int t, GF2Matrix g){
        super(false, null);
        this.n = n;
        this.t = t;
        this.g = new GF2Matrix(g);
    }
    
}

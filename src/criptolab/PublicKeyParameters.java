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
    
    // longitud del código
    private int n;

    // Cantidad de errores que corrije el código
    private int t;

    // Matriz G
    private GF2Matrix g;
    
    public PublicKeyParameters(int n, int t, GF2Matrix g){
        super(false, null);
        this.n = n;
        this.t = t;
        this.g = new GF2Matrix(g);
    }

    int getN() {
        return n;
    }

    //Dimensión del código
    int getK() {
        return g.getNumRows();
    }

    int getT() {
        return t;
    }

    GF2Matrix getG() {
        return g;
    }
    
}

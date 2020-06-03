using Assets.Crypto.Blowfish;
using System;
using System.Collections;
using System.Text;
using UnityEngine;
using System.Linq;

public class TwoFish : MonoBehaviour
{
    //Reprezentacja RS dla Q0 w postaci decimal
    byte[] T0 = { 8, 1, 7, 13, 6, 15, 3, 2, 0, 11, 5, 9, 14, 12, 10, 4 };
    byte[] T1 = { 14, 12, 11, 8, 1, 2, 3, 5, 15, 4, 10, 6, 7, 0, 9, 13 };
    byte[] T2 = { 11, 10, 5, 14, 6, 13, 9, 0, 12, 8, 15, 3, 2, 4, 7, 1 };
    byte[] T3 = { 13, 7, 15, 4, 1, 2, 6, 14, 9, 11, 3, 0, 8, 5, 12, 10 };
    //Reprezentacja RS dla Q1 w postaci decimal
    byte[] T0_q1 = { 2, 8, 11, 13, 15, 7, 6, 14, 3, 1, 9, 4, 0, 10, 12, 5 };
    byte[] T1_q1 = { 1, 15, 2, 11, 4, 12, 3, 7, 6, 13, 10, 5, 15, 9, 0, 8 };
    byte[] T2_q1 = { 4, 12, 7, 5, 1, 6, 9, 10, 0, 14, 13, 8, 2, 11, 3, 15 };
    byte[] T3_q1 = { 11, 9, 5, 1, 12, 3, 13, 14, 6, 4, 7, 15, 2, 0, 8, 10 };
    
    //2^32 w hex
    BitArray modArr = ConvertHexToBitArray("100000000");
    //Klucz S używany w S-boxach
    BitArray[] Skeys;
    //1 część klucza K2r+8
    BitArray[] SubKeys1;
    //2 część klucza K2r+9
    BitArray[] SubKeys2;
    //klucz dla wejściowego Whitening 
    BitArray[] InputWhiteningKeys;
    //klucz dla wyjściowego Whitening
    BitArray[] OutputWhiteningKeys;

    /// <summary>
    /// Reprezentacja 1 fazy Input Whitening - przeznaczona do testów
    /// </summary>
    public BitArray InputWhitening(BitArray plainText, BitArray keySchedule)
    {
        /*Debug.Log(plainText.Length + ":" + keySchedule.Length);
        Debug.Log(ConvertToHex(plainText));
        Debug.Log(ConvertToHex(keySchedule));*/


        BitArray[] plainTextSplited = Enumerable
            .Range(0, plainText.Length / 32)
            .Select(offset => CopySlice(plainText, offset * 32, 32))
            .ToArray();

        BitArray P0 = plainTextSplited[0];
        BitArray P1 = plainTextSplited[1];
        BitArray P2 = plainTextSplited[2];
        BitArray P3 = plainTextSplited[3];



        BitArray[] keyScheduleSplited = Enumerable
            .Range(0, keySchedule.Length / 32)
            .Select(offset => CopySlice(keySchedule, offset * 32, 32))
            .ToArray();

        BitArray K0 = keyScheduleSplited[0];
        BitArray K1 = keyScheduleSplited[1];
        BitArray K2 = keyScheduleSplited[2];
        BitArray K3 = keyScheduleSplited[3];

        BitArray R0 = XOR(P0, K0);
        BitArray R1 = XOR(P1, K1);
        BitArray R2 = XOR(P2, K2);
        BitArray R3 = XOR(P3, K3);

        BitArray R_finish = AddAppend(AddAppend(AddAppend(R0, R1), R2), R3);
        /*//Debug.Log(ConvertToHex(P0));
        //Debug.Log(ConvertToHex(K0));
        Debug.Log(ConvertToHex(R_finish));*/
        return R_finish;
    }

    /// <summary>
    /// Reprezentacja 1 fazy Input Whitening
    /// <param name="plainText"> 128 bit teks do zakodowania</param>
    /// </summary>
    public BitArray[] InputWhitening(BitArray plainText)
    {
        //Debug.Log(plainText.Length);

        //Podział 128 bit plain text na 4 o wielkości 32 bit
        BitArray[] plainTextSplited = Enumerable
            .Range(0, plainText.Length / 32)
            .Select(offset => CopySlice(plainText, offset * 32, 32))
            .ToArray();

        BitArray P0 = plainTextSplited[0];
        BitArray P1 = plainTextSplited[1];
        BitArray P2 = plainTextSplited[2];
        BitArray P3 = plainTextSplited[3];




        BitArray K0 = InputWhiteningKeys[0];
        BitArray K1 = InputWhiteningKeys[1];
        BitArray K2 = InputWhiteningKeys[2];
        BitArray K3 = InputWhiteningKeys[3];

        //XOR z kluczami
        BitArray R0 = XOR(P0, K0);
        BitArray R1 = XOR(P1, K1);
        BitArray R2 = XOR(P2, K2);
        BitArray R3 = XOR(P3, K3);

        //BitArray R_finish = AddAppend(AddAppend(AddAppend(R0, R1), R2), R3);
        //Debug.Log(ConvertToHex(P0));
        //Debug.Log(ConvertToHex(K0));
        //Debug.Log(R_finish.Length);
        //Debug.Log(ConvertToHex(R_finish));
        return new BitArray[] { R0, R1, R2, R3 };
    }

    /// <summary>
    /// Reprezentacja ostatniej fazy output whitening
    /// <param name="P0"> 32 bit</param>
    /// <param name="P1"> 32 bit</param>
    /// <param name="P2"> 32 bit</param>
    /// <param name="P3"> 32 bit</param>
    /// </summary>
    public BitArray[] OutputWhitening(BitArray P0, BitArray P1, BitArray P2, BitArray P3)
    {

        BitArray K0 = OutputWhiteningKeys[0];
        BitArray K1 = OutputWhiteningKeys[1];
        BitArray K2 = OutputWhiteningKeys[2];
        BitArray K3 = OutputWhiteningKeys[3];

        BitArray R0 = XOR(P0, K0);
        BitArray R1 = XOR(P1, K1);
        BitArray R2 = XOR(P2, K2);
        BitArray R3 = XOR(P3, K3);

        //BitArray R_finish = AddAppend(AddAppend(AddAppend(R0, R1), R2), R3);
        //Debug.Log(ConvertToHex(P0));
        //Debug.Log(ConvertToHex(K0));
        //Debug.Log(R_finish.Length);
        //Debug.Log(ConvertToHex(R_finish));
        return new BitArray[] { R0, R1, R2, R3 };
    }

    /// <summary>
    /// Reprezentacja funkcji F 
    /// <param name="R0"> 32 bit slowo otrzymane z poprzedniej rundy</param>
    /// <param name="R1"> 32 bit slowo otrzymane z poprzedniej rundy</param>
    /// <param name="round">numer rundy</param>
    /// </summary>
    public BitArray[] F_Function(BitArray R0, BitArray R1, int round)
    { 
        //wynik funkcji G dla R0 z kluczami S0,S1
        BitArray T0 = G_function(FillTo32bit(R0),Skeys[0],Skeys[1]);
        //wynik funkcji G dla R1 <<<8 z kluczami S0,S1
        BitArray T1 = G_function(FillTo32bit(ShiftLft(R1, 8)), Skeys[0], Skeys[1]);
        //PHT oraz XOR z kluczami
        BitArray[] F = PHT(T0, T1, SubKeys1[round], SubKeys2[round]);
        return F;
    }

    /// <summary>
    /// Reprezentacja funkcji G
    /// <param name="R"> 32 bit slowo otrzymane z F</param>
    /// <param name="S0">1 część klucza S</param>
    /// <param name="S1">2 część klucza S</param>
    /// </summary>
    public BitArray G_function(BitArray R, BitArray S0, BitArray S1)
    {
       // Debug.Log("G");
       // Debug.Log(R.Length);

        //Obliczenie S-Boxów
        BitArray[] sBoxes = S_Box(R, S0, S1);

        BitArray SB0 = sBoxes[0];

        BitArray SB1 = sBoxes[1];

        BitArray SB2 = sBoxes[2];

        BitArray SB3 = sBoxes[3];

        /*DebugBits(SB0);
        DebugBits(SB1);
        DebugBits(SB2);
        DebugBits(SB3);*/


        BitArray EF = ConvertHexToBitArray("EF");
        BitArray _5B = ConvertHexToBitArray("5B");

        /*Debug.Log("SB0:");
        DebugBits(SB0);
        Debug.Log("SB1 * EF =");
        DebugBits(EF);
        DebugBits(SB1);
        DebugBits(GMul(SB1, EF));*/

        /*Debug.Log("SB2 * 5B:");
        DebugBits(GMul(SB2, _5B));

        Debug.Log("SB3 * 5B:");
        DebugBits(GMul(SB3, _5B));*/

        //Wykonanie MDS
        BitArray vec1 = XOR4(SB0, GMul(SB1, EF), GMul(SB2, _5B), GMul(SB3, _5B));
        BitArray vec2 = XOR4(GMul(SB0, _5B), GMul(SB1, EF), GMul(SB2, EF), SB3);
        BitArray vec3 = XOR4(GMul(SB0, EF), GMul(SB1, _5B), SB2, GMul(SB3, EF));
        BitArray vec4 = XOR4(GMul(SB0, EF), SB1, GMul(SB2, EF), GMul(SB3, _5B));

        /*Debug.Log(getIntFromBitArrayInv(modPol(vec1)));
        Debug.Log(getIntFromBitArrayInv(modPol(vec2)));
        Debug.Log(getIntFromBitArrayInv(modPol(vec3)));
        Debug.Log(getIntFromBitArrayInv(modPol(vec4)));*/
        vec1 = ConvertTo8bitArray(getIntFromBitArrayInv(modPol(vec1)));
        vec2 = ConvertTo8bitArray(getIntFromBitArrayInv(modPol(vec2)));
        vec3 = ConvertTo8bitArray(getIntFromBitArrayInv(modPol(vec3)));
        vec4 = ConvertTo8bitArray(getIntFromBitArrayInv(modPol(vec4)));

        //Debug.Log(ConvertToHex(vec1)+ConvertToHex(vec2)+ ConvertToHex(vec3) + ConvertToHex(vec4));

        return AddAppend(AddAppend(AddAppend(vec1, vec2), vec3), vec4);
    }

    /// <summary>
    /// Reprezentacja funkcji S-Box
    /// <param name="X"> 32 bit slowo otrzymane z G</param>
    /// <param name="S0">1 część klucza S</param>
    /// <param name="S1">2 część klucza S</param>
    /// </summary>
    public BitArray[] S_Box(BitArray X, BitArray S0, BitArray S1)
    {
        //podział na 4 - 8 bitowe słowa
        BitArray[] X_splited = Enumerable
            .Range(0, X.Length / 8)
            .Select(offset => CopySlice(X, offset * 8, 8))
            .ToArray();

        /*DebugBits(X);
        DebugBits(S0);
        DebugBits(S1);*/

        BitArray x0 = X_splited[0];
        BitArray x1 = X_splited[1];
        BitArray x2 = X_splited[2];
        BitArray x3 = X_splited[3];

        /*DebugBits(x0);
        DebugBits(x1);
        DebugBits(x2);
        DebugBits(x3);*/

        //wykoanie 1 części w S-box 
        x0 = q0(x0);
        x1 = q1(x1);
        x2 = q0(x2);
        x3 = q1(x3);

        /*Debug.Log("Pierwsze przejscie Q");
        DebugBits(x0);
        DebugBits(x1);
        DebugBits(x2);
        DebugBits(x3);*/

        BitArray X0 = AddAppend(AddAppend(AddAppend(x0, x1), x2), x3);

        //DebugBits(X0);

        //XOR z kluczem S0
        X0 = XOR( X0,S0);

        /*Debug.Log("Xored S0");
        DebugBits(X0);*/

        //ponowny podział na 8 bit słowa
        X_splited = Enumerable
            .Range(0, X0.Length / 8)
            .Select(offset => CopySlice(X0, offset * 8, 8))
            .ToArray();

        x0 = X_splited[0];
        x1 = X_splited[1];
        x2 = X_splited[2];
        x3 = X_splited[3];
        /*Debug.Log("X-y po XOR");
        DebugBits(x0);
        DebugBits(x1);
        DebugBits(x2);
        DebugBits(x3);*/

        //wykonanie 2 przejścia Q
        x0 = q0(x0);
        x1 = q0(x1);
        x2 = q1(x2);
        x3 = q1(x3);

        /*Debug.Log("2 przejscie Q");
        DebugBits(x0);
        DebugBits(x1);
        DebugBits(x2);
        DebugBits(x3);
        */
        BitArray X1 = AddAppend(AddAppend(AddAppend(x0, x1), x2), x3);
        //DebugBits(X1);
        //Debug.Log("XORED S1");

        //XOR z kluczem S1
        X1 = XOR(X1,S1);
        //DebugBits(X1);

        X_splited = Enumerable
            .Range(0, X1.Length / 8)
            .Select(offset => CopySlice(X1, offset * 8, 8))
            .ToArray();

        //Debug.Log("X-y");
        x0 = X_splited[0];
        x1 = X_splited[1];
        x2 = X_splited[2];
        x3 = X_splited[3];

        /*DebugBits(x0);
        DebugBits(x1);
        DebugBits(x2);
        DebugBits(x3);*/

        //Ostatnie przejście Q
        x0 = q1(x0);
        x1 = q0(x1);
        x2 = q1(x2);
        x3 = q0(x3);

        /*Debug.Log("last q");

        DebugBits(x0);
        DebugBits(x1);
        DebugBits(x2);
        DebugBits(x3);*/
        //Debug.Log(ConvertToHex(x0) + ConvertToHex(x1) + ConvertToHex(x2) + ConvertToHex(x3));

        return new BitArray[] { x0, x1, x2, x3 };
    }

    /// <summary>
    /// Reprezentacja funkcji H bez MDS
    /// <param name="I"> 32 bit slowo np 2i +1 </param>
    /// <param name="M0">1 część klucza M</param>
    /// <param name="M1">2 część klucza M</param>
    /// </summary>
    public BitArray[] function_H(BitArray I, BitArray M0, BitArray M1)
    {
        //wartości 2i lub 2i+1 do generacji klucza
        BitArray x0 = (BitArray)I.Clone();
        BitArray x1 = (BitArray)I.Clone();
        BitArray x2 = (BitArray)I.Clone();
        BitArray x3 = (BitArray)I.Clone();

        /*DebugBits(x0);
        DebugBits(x1);
        DebugBits(x2);
        DebugBits(x3);*/

        //1 przejście Q
        x0 = q0(ConvertTo8bitArray(getIntFromBitArrayInv(x0)));
        x1 = q1(ConvertTo8bitArray(getIntFromBitArrayInv(x1)));
        x2 = q0(ConvertTo8bitArray(getIntFromBitArrayInv(x2)));
        x3 = q1(ConvertTo8bitArray(getIntFromBitArrayInv(x3)));

        /*Debug.Log("pierwsze przejście Q");
        DebugBits(x0);
        DebugBits(x1);
        DebugBits(x2);
        DebugBits(x3);*/

        BitArray X0 = AddAppend(AddAppend(AddAppend(x0, x1), x2), x3);

        /*Debug.Log("Xor z M1");
        DebugBits(X0);
        DebugBits(M1);*/

        //XOR z kluczem M1 lub M3
        X0 = XOR(X0, M1);
        // Debug.Log("Xored S0");
        //DebugBits(X0);

        BitArray[] X_splited = Enumerable
            .Range(0, X0.Length / 8)
            .Select(offset => CopySlice(X0, offset * 8, 8))
            .ToArray();

        x0 = X_splited[0];
        x1 = X_splited[1];
        x2 = X_splited[2];
        x3 = X_splited[3];

        /*Debug.Log("2 - q przed");
        DebugBits(x0);
        DebugBits(x1);
        DebugBits(x2);
        DebugBits(x3);*/

        // 2 przejście Q
        x0 = q0(x0);
        x1 = q0(x1);
        x2 = q1(x2);
        x3 = q1(x3);
        /*Debug.Log("2 - q po");
        DebugBits(x0);
        DebugBits(x1);
        DebugBits(x2);
        DebugBits(x3);*/

        BitArray X1 = AddAppend(AddAppend(AddAppend(x0, x1), x2), x3);
        /*Debug.Log("Xor X1 z M0");
        DebugBits(X1);
        DebugBits(M0);
        Debug.Log("XORED X1");*/

        //XOR z kluczem M0 lub M2
        X1 = XOR(X1, M0);
        //DebugBits(X1);

        X_splited = Enumerable
            .Range(0, X1.Length / 8)
            .Select(offset => CopySlice(X1, offset * 8, 8))
            .ToArray();

        //Debug.Log("last q before:");

        x0 = X_splited[0];
        x1 = X_splited[1];
        x2 = X_splited[2];
        x3 = X_splited[3];

        /*DebugBits(x0);
        DebugBits(x1);
        DebugBits(x2);
        DebugBits(x3);*/

        //Ostatnie przejście Q
        x0 = q1(x0);
        x1 = q0(x1);
        x2 = q1(x2);
        x3 = q0(x3);

        /*DebugBits(x0);
        DebugBits(x1);
        DebugBits(x2);
        DebugBits(x3);*/


        return new BitArray[] { x0, x1, x2, x3 };
    }

    /// <summary>
    /// Reprezentacja funkcji PHT wraz XORem z kluczami
    /// <param name="T0"> Wyjście z G 32 bit</param>
    /// <param name="T1"> Wyjście z G 32 bit</param>
    /// <param name="Key2r8" >Klucz K2r+8</param>
    /// <param name="Key2r9" >Klucz K2r+9</param>
    /// </summary>
    public BitArray[] PHT(BitArray T0, BitArray T1, BitArray Key2r8, BitArray Key2r9)
    {

        //a' = a+b mod 2^32
        BitArray a = MOD_bit(XOR(T0, T1), modArr);
        //b' = a +2b mod 2^32
        BitArray b = MOD_bit(XOR(T0, MUL_bit(T1, ConvertHexToBitArray("2"))), modArr);
        //DebugBits(MOD_bit( XOR(XOR(T0, T1), Key2r8),modArr));
        //DebugBits(MOD_bit(XOR(XOR(T0, MUL_bit( T1, ConvertHexToBitArray("2"))), Key2r9), modArr));

        //XOR z kluczem
        return new BitArray[] { XOR(a,Key2r8), XOR(b, Key2r9)};
    }

    /// <summary>
    /// Reprezentacja funkcji PHT dla funkcji H
    /// <param name="T0"> Wyjście z H 32 bit</param>
    /// <param name="T1"> Wyjście z H 32 bit</param>
    /// </summary>
    public BitArray[] PHT(BitArray T0, BitArray T1)
    {
        /*DebugBits(modArr);
        DebugBits(T0);
        DebugBits(T1);
        DebugBits(XOR(T0, T1));*/

        //a' = a+b mod 2^32
        BitArray a = MOD_bit(XOR(T0, T1), modArr);

        /* 
        DebugBits(MUL_bit(T1, ConvertHexToBitArray("2")));
        DebugBits(T0);
        DebugBits(XOR(T0, MUL_bit(T1, ConvertHexToBitArray("2"))));
        DebugBits(MOD_bit(XOR(T0, MUL_bit(T1, ConvertHexToBitArray("2"))),modArr));*/

        //b' = <<<< 8 (a +2b) mod 2^32
        BitArray b = ShiftLft(MOD_bit(XOR(T0, MUL_bit(T1, ConvertHexToBitArray("2"))), modArr), 9);
        //DebugBits(b);

        return new BitArray[] { a, b };
    }

    /// <summary>
    /// Reprezentacja Q0 dla S-boxów
    /// <param name="Ic"> 8 bit słowo z S-box</param>
    /// </summary>
    public BitArray q0(BitArray IC)
    {
        //podział na 2 4bit słowa
        BitArray[] IC_splited = Enumerable
        .Range(0, IC.Length / 4)
        .Select(offset => CopySlice(IC, offset * 4, 4))
        .ToArray();

        BitArray a_0 = IC_splited[0];
        BitArray b_0 = IC_splited[1];
        
        /*Debug.Log("a0");
        DebugBits(a_0);
        Debug.Log("b0");
        DebugBits(b_0);*/

        // a1 = a0 XOR b0
        BitArray a_1 = XOR(b_0,a_0);

        /*Debug.Log("a1");
        DebugBits(a_1);*/

        // 8a0 mod 16
        int a8mod16 = 8 * getIntFromBitArrayInv(a_0) % 16;

        
        /*Debug.Log("8 a0 mod 16");
        Debug.Log(8* getIntFromBitArrayInv(a_0) % 16);
        DebugBits(ConvertTo4bitArray(a8mod16));*/

        /*Debug.Log("ROR (b0,1)");
        DebugBits(new BitArray(ShiftRight(b_0, 1)));*/

        //b1 = a0 xor ROR4(b0,1) xor 8 a0 mod 16
        BitArray b_1 = XOR(XOR(a_0, new BitArray(ShiftRight(b_0, 1))), ConvertTo4bitArray(a8mod16));

        /*Debug.Log("b1");
        DebugBits(b_1);*/
        
        //pobranie a2 i b2 z tabeli  t0[a1], t1[b1]
        BitArray a_2 = ConvertTo4bitArray(T0[getIntFromBitArrayInv(a_1)]);
        BitArray b_2 = ConvertTo4bitArray(T1[getIntFromBitArrayInv(b_1)]);

        /*Debug.Log("a2");
        DebugBits(a_2);
        Debug.Log("b2");
        DebugBits(b_2);*/

        //a3 = b2 xor a2
        BitArray a_3 = XOR(b_2, a_2);

        /*Debug.Log("XOR a3, b3");
        DebugBits(a_3);*/

        //8 a2 mod 16
        int a8mod16_3 = 8 * getIntFromBitArrayInv(a_2) % 16;
        /*Debug.Log("8 a3 mod 16");
        Debug.Log(a8mod16_3);*/

        //b3 =a2 xor ROR4(b2,1) xor 8 a2 mod 16
        BitArray b_3 = XOR(XOR(ConvertTo4bitArray(a8mod16_3),  new BitArray(ShiftRight(b_2, 1))),a_2);

        /*Debug.Log("b3");
        DebugBits(b_3);*/

        //pobranie wartości z tabeli T2[a3], t3[b3]
        BitArray a_4 = ConvertTo4bitArray(T2[getIntFromBitArrayInv(a_3)]);
        BitArray b_4 = ConvertTo4bitArray(T3[getIntFromBitArrayInv(b_3)]);

        /*Debug.Log("a4");
        DebugBits(a_4);
        Debug.Log("b4");
        DebugBits(b_4);*/

        //y = 16 b4 + a4 (zamiana)
        BitArray y = ConvertTo8bitArray((16 * getIntFromBitArrayInv(b_4)) + getIntFromBitArrayInv(a_4));

        //DebugBits(y);
        return y;
    }

    /// <summary>
    /// Reprezentacja Q1 dla S-boxów (tak samo jak w Q1 tylko wartości z tabeli prim)
    /// <param name="Ic"> 8 bit słowo z S-box</param>
    /// </summary>
    public BitArray q1(BitArray IC)
    {
        BitArray[] IC_splited = Enumerable
        .Range(0, IC.Length / 4)
        .Select(offset => CopySlice(IC, offset * 4, 4))
        .ToArray();

        BitArray a_0 = IC_splited[0];
        BitArray b_0 = IC_splited[1];

        /*Debug.Log("a0");
        DebugBits(a_0);
        Debug.Log("b0");
        DebugBits(b_0);*/

        BitArray a_1 = XOR(b_0, a_0);

        /*Debug.Log("a1");
        DebugBits(a_1);*/

        int a8mod16 = 8 * getIntFromBitArrayInv(a_0) % 16;

        
        /*Debug.Log("8 a0 mod 16");
        Debug.Log(8* getIntFromBitArrayInv(a_0) % 16);
        DebugBits(ConvertTo4bitArray(a8mod16));

        Debug.Log("ROR (b0,1)");
        DebugBits(new BitArray(ShiftRight(b_0, 1)));*/

        BitArray b_1 = XOR(XOR(a_0, new BitArray(ShiftRight(b_0, 1))), ConvertTo4bitArray(a8mod16));

        /*Debug.Log("b1");
        DebugBits(b_1);*/

        BitArray a_2 = ConvertTo4bitArray(T0_q1[getIntFromBitArrayInv(a_1)]);
        BitArray b_2 = ConvertTo4bitArray(T1_q1[getIntFromBitArrayInv(b_1)]);

        /*Debug.Log("a2");
        DebugBits(a_2);
        Debug.Log("b2");
        DebugBits(b_2);*/

        BitArray a_3 = XOR(b_2, a_2);

        /*Debug.Log("XOR a3, b3");
        DebugBits(a_3);*/

        int a8mod16_3 = 8 * getIntFromBitArrayInv(a_2) % 16;
        /*Debug.Log("8 a3 mod 16");
        Debug.Log(a8mod16_3);*/

        /*Debug.Log("ROR b2 1");
        DebugBits(new BitArray(ShiftRight(b_2, 1)));*/

        BitArray b_3 = XOR(XOR(ConvertTo4bitArray(a8mod16_3), new BitArray(ShiftRight(b_2, 1))), a_2);

        /*Debug.Log("b3");
        DebugBits(b_3);*/

        BitArray a_4 = ConvertTo4bitArray(T2_q1[getIntFromBitArrayInv(a_3)]);
        BitArray b_4 = ConvertTo4bitArray(T3_q1[getIntFromBitArrayInv(b_3)]);

        /*Debug.Log("a4");
        DebugBits(a_4);
        Debug.Log("b4");
        DebugBits(b_4);*/

        BitArray y = ConvertTo8bitArray(16 * getIntFromBitArrayInv(b_4) + getIntFromBitArrayInv(a_4));

        //DebugBits(y);
        return y;
    }

    /// <summary>
    /// Generacja kluczy S
    /// <param name="M"> 128 bit klucz</param>
    /// </summary>
    public BitArray[] SKeyGenerator(BitArray M)
    {
        /*Debug.Log("S Key generator");
        Debug.Log(M.Length);*/

        BitArray[] M_splited = Enumerable
            .Range(0, M.Length / 8)
            .Select(offset => CopySlice(M, offset * 8, 8))
            .ToArray();

        //wartości z RS
        BitArray A4 = ConvertHexToBitArray("A4");
        BitArray _55 = ConvertHexToBitArray("55");
        BitArray _87 = ConvertHexToBitArray("87");
        BitArray _5A = ConvertHexToBitArray("5A");
        BitArray _58 = ConvertHexToBitArray("58");

        BitArray DB = ConvertHexToBitArray("DB");
        BitArray _9E = ConvertHexToBitArray("9E");
        BitArray _56 = ConvertHexToBitArray("56");
        BitArray _82 = ConvertHexToBitArray("82");
        BitArray F3 = ConvertHexToBitArray("F3");
        BitArray _1E = ConvertHexToBitArray("1E");

        BitArray C6 = ConvertHexToBitArray("C6");
        BitArray _68 = ConvertHexToBitArray("68");
        BitArray E5 = ConvertHexToBitArray("E5");
        BitArray _02 = ConvertHexToBitArray("02");
        BitArray A1 = ConvertHexToBitArray("A1");
        BitArray FC = ConvertHexToBitArray("FC");
        BitArray C1 = ConvertHexToBitArray("C1");
        BitArray _47 = ConvertHexToBitArray("47");
        BitArray AE = ConvertHexToBitArray("AE");
        BitArray _3D = ConvertHexToBitArray("3D");
        BitArray _19 = ConvertHexToBitArray("19");
        BitArray _03 = ConvertHexToBitArray("03");

        /*Debug.Log("??");

        Debug.Log(ConvertToHex(M_splited[8]) + "* A4 =" + ConvertToHex(ConvertTo8bitArray(getIntFromBitArrayInv(GMulRS(M_splited[8], A4)))));
        Debug.Log(ConvertToHex(M_splited[9]) + "* 56 =" + ConvertToHex(ConvertTo8bitArray(getIntFromBitArrayInv(GMulRS(M_splited[9], _56)))));
        Debug.Log(ConvertToHex(M_splited[10]) + "* 82 =" + ConvertToHex(ConvertTo8bitArray(getIntFromBitArrayInv(GMulRS(M_splited[10], _82)))));
        Debug.Log(ConvertToHex(M_splited[11]) + "* F3 =" + ConvertToHex(ConvertTo8bitArray(getIntFromBitArrayInv(GMulRS(M_splited[11], F3)))));
        Debug.Log(ConvertToHex(M_splited[12]) + "* 1E =" + ConvertToHex(ConvertTo8bitArray(getIntFromBitArrayInv(GMulRS(M_splited[12], _1E)))));
        Debug.Log(ConvertToHex(M_splited[13]) + "* C6 =" + ConvertToHex(ConvertTo8bitArray(getIntFromBitArrayInv(GMulRS(M_splited[13], C6)))));
        Debug.Log(ConvertToHex(M_splited[14]) + "* 68 =" + ConvertToHex(ConvertTo8bitArray(getIntFromBitArrayInv(GMulRS(M_splited[14], _68)))));
        Debug.Log(ConvertToHex(M_splited[15]) + "* E5 =" + ConvertToHex(ConvertTo8bitArray(getIntFromBitArrayInv(GMulRS(M_splited[15], E5)))));*/

        // przemnożenie z RS
        BitArray S00 = XOR(XOR4(M_splited[0], GMulRS(M_splited[1], A4), GMulRS(M_splited[2], _55), GMulRS(M_splited[3], _87)),
            XOR4(GMulRS(M_splited[4], _5A), GMulRS(M_splited[5], _58), GMulRS(M_splited[6], DB), GMulRS(M_splited[7], _9E)));
        BitArray S01 = XOR(XOR4(GMulRS( M_splited[0],A4), GMulRS(M_splited[1], _56), GMulRS(M_splited[2], _82), GMulRS(M_splited[3], F3)),
            XOR4(GMulRS(M_splited[4], _1E), GMulRS(M_splited[5], C6), GMulRS(M_splited[6], _68), GMulRS(M_splited[7], E5)));
        BitArray S02 = XOR(XOR4(GMulRS(M_splited[0], _02), GMulRS(M_splited[1], A1), GMulRS(M_splited[2], FC), GMulRS(M_splited[3], C1)),
            XOR4(GMulRS(M_splited[4], _47), GMulRS(M_splited[5], AE), GMulRS(M_splited[6], _3D), GMulRS(M_splited[7], _19)));
        BitArray S03 = XOR(XOR4(GMulRS(M_splited[0], A4), GMulRS(M_splited[1], _55), GMulRS(M_splited[2], _87), GMulRS(M_splited[3], _5A)),
            XOR4(GMulRS(M_splited[4], _58), GMulRS(M_splited[5], DB), GMulRS(M_splited[6], _9E), GMulRS(M_splited[7], _03)));


        BitArray S10 = XOR(XOR4(M_splited[8], GMulRS(M_splited[9], A4), GMulRS(M_splited[10], _55), GMulRS(M_splited[11], _87)),
            XOR4(GMulRS(M_splited[12], _5A), GMulRS(M_splited[13], _58), GMulRS(M_splited[14], DB), GMulRS(M_splited[15], _9E)));

        BitArray S11 = XOR(XOR4(GMulRS(M_splited[8], A4), GMulRS(M_splited[9], _56), GMulRS(M_splited[10], _82), GMulRS(M_splited[11], F3)),
            XOR4(GMulRS(M_splited[12], _1E), GMulRS(M_splited[13], C6), GMulRS(M_splited[14], _68), GMulRS(M_splited[15], E5)));

        BitArray S12 = XOR(XOR4(GMulRS(M_splited[8], _02), GMulRS(M_splited[9], A1), GMulRS(M_splited[10], FC), GMulRS(M_splited[11], C1)),
            XOR4(GMulRS(M_splited[12], _47), GMulRS(M_splited[13], AE), GMulRS(M_splited[14], _3D), GMulRS(M_splited[15], _19)));

        BitArray S13 = XOR(XOR4(GMulRS(M_splited[8], A4), GMulRS(M_splited[9], _55), GMulRS(M_splited[10], _87), GMulRS(M_splited[11], _5A)),
            XOR4(GMulRS(M_splited[12], _58), GMulRS(M_splited[13], DB), GMulRS(M_splited[14], _9E), GMulRS(M_splited[15], _03)));

        /*Debug.Log(ConvertToHex(ConvertTo8bitArray(getIntFromBitArrayInv(modPolRS(S00)))));
        Debug.Log(ConvertToHex(ConvertTo8bitArray(getIntFromBitArrayInv(modPolRS(S01)))));
        Debug.Log(ConvertToHex(ConvertTo8bitArray(getIntFromBitArrayInv(modPolRS(S02)))));
        Debug.Log(ConvertToHex(ConvertTo8bitArray(getIntFromBitArrayInv(modPolRS(S03)))));

        Debug.Log(ConvertToHex(ConvertTo8bitArray(getIntFromBitArrayInv(modPolRS(S10)))));
        Debug.Log(ConvertToHex(ConvertTo8bitArray(getIntFromBitArrayInv(modPolRS(S11)))));
        Debug.Log(ConvertToHex(ConvertTo8bitArray(getIntFromBitArrayInv(modPolRS(S12)))));
        Debug.Log(ConvertToHex(ConvertTo8bitArray(getIntFromBitArrayInv(modPolRS(S13)))));*/

        /*DebugBits(S00);
        DebugBits(S01);
        DebugBits(S02);
        DebugBits(S03);

        DebugBits(S10);
        DebugBits(S11);
        DebugBits(S12);
        DebugBits(S13);*/
        /*Debug.Log(ConvertToHex(ConvertTo8bitArray(getIntFromBitArrayInv(modPolRS(S03)))) + ConvertToHex(ConvertTo8bitArray(getIntFromBitArrayInv(modPolRS(S02)))) +
            ConvertToHex(ConvertTo8bitArray(getIntFromBitArrayInv(modPolRS(S01)))) + ConvertToHex(ConvertTo8bitArray(getIntFromBitArrayInv(modPolRS(S00)))));
        Debug.Log(ConvertToHex(ConvertTo8bitArray(getIntFromBitArrayInv(modPolRS(S13)))) + ConvertToHex(ConvertTo8bitArray(getIntFromBitArrayInv(modPolRS(S12)))) +
            ConvertToHex(ConvertTo8bitArray(getIntFromBitArrayInv(modPolRS(S11)))) + ConvertToHex(ConvertTo8bitArray(getIntFromBitArrayInv(modPolRS(S10)))));*/
        
        //Odwrócona kolejność kluczy
        BitArray first = AddAppend(AddAppend(AddAppend(ConvertTo8bitArray(getIntFromBitArrayInv(modPolRS(S03))), ConvertTo8bitArray(getIntFromBitArrayInv(modPolRS(S02)))),
            ConvertTo8bitArray(getIntFromBitArrayInv(modPolRS(S01)))), ConvertTo8bitArray(getIntFromBitArrayInv(modPolRS(S00))));
        BitArray second = AddAppend(AddAppend(AddAppend(ConvertTo8bitArray(getIntFromBitArrayInv(modPolRS(S13))), ConvertTo8bitArray(getIntFromBitArrayInv(modPolRS(S12)))),
            ConvertTo8bitArray(getIntFromBitArrayInv(modPolRS(S11)))), ConvertTo8bitArray(getIntFromBitArrayInv(modPolRS(S10))));

        return new BitArray[] {first,second };
    }

    /// <summary>
    /// Generacja kluczy K dla danej rundy (generuje 2 klucze)
    /// <param name="M"> 128 bit klucz</param>
    /// <param name="i">numer rundy</param>
    /// </summary>
    public BitArray[] SubkeysKGenerator(int i, BitArray M)
    {
        //Debug.Log(" K key generator");
        BitArray[] M_splited = Enumerable
            .Range(0, M.Length / 32)
            .Select(offset => CopySlice(M, offset * 32, 32))
            .ToArray();

        BitArray M_even = AddAppend(M_splited[0], M_splited[2]);
        BitArray M_odd = AddAppend(M_splited[1], M_splited[3]);

        /*Debug.Log("Even , Odd:");
        Debug.Log(ConvertToHex(M_even));
        Debug.Log(ConvertToHex(M_odd));*/

        BitArray[] wynik = function_H(ConvertTo8bitArray(2*i), M_splited[0], M_splited[2]);
        BitArray[] wynik1 = function_H(ConvertTo8bitArray(2*i +1), M_splited[1], M_splited[3]);
        BitArray MDS1 = MDS(wynik[0], wynik[1], wynik[2], wynik[3]);
        BitArray MDS2 = MDS(wynik1[0], wynik1[1], wynik1[2], wynik1[3]);
        BitArray ROL8 = ShiftLft(MDS2, 8);

        return PHT(MDS1, ROL8);
        
    }

    /// <summary>
    /// Generacja kluczy S i K - zapis w Skeys, InputWhiteningKeys, OutputWhiteningKeys, SubKeys1, SubKeys2
    /// <param name="M"> 128 bit klucz</param>
    /// </summary>
    public void GenerateKeys(BitArray M)
    {
        Skeys = SKeyGenerator(M);//generacja kluczy S
        BitArray[] wt = SubkeysKGenerator(0, M);//1 część kluczy dla input whitening
        BitArray[] wt1 = SubkeysKGenerator(1, M);//2 część kluczy dla input whitening
        InputWhiteningKeys = new BitArray[] { wt[0], wt[1], wt1[0], wt1[1] };

        BitArray[] owt = SubkeysKGenerator(2, M);//1 część kluczy dla output whitening
        BitArray[] owt1 = SubkeysKGenerator(3, M);//2 część kluczy dla output whitening
        OutputWhiteningKeys = new BitArray[] { owt[0], owt[1], owt1[0], owt1[1] };

        //generacja kluczy dla 16 rund - łącznie 32
        SubKeys1 = new BitArray[16];
        SubKeys2 = new BitArray[16];
        int j = 0;
        for (int i=4; i < 20; i++)
        {
            BitArray[] subKey = SubkeysKGenerator(i, M);
            SubKeys1[j] = subKey[0];
            SubKeys2[j] = subKey[1];
            j++;
        }

        //32 klucze K + 4 whitening + 4 whitening out = 40

    }

    /// <summary>
    /// Wykonanie mnożenia z macierzą MDS w x^8 x^6 x^5 + x^3 +1 GF(2^8)
    /// <param name="SB0"> 8 bit wyjście z s-box</param>
    /// <param name="SB1"> 8 bit wyjście z s-box</param>
    /// <param name="SB2"> 8 bit wyjście z s-box</param>
    /// <param name="SB3"> 8 bit wyjście z s-box</param>
    /// </summary>
    public BitArray MDS(BitArray SB0, BitArray SB1, BitArray SB2, BitArray SB3)
    {
        BitArray EF = ConvertHexToBitArray("EF");
        BitArray _5B = ConvertHexToBitArray("5B");

        //mnożenie w GF i sumowanie
        BitArray vec1 = XOR4(SB0, GMul(SB1, EF), GMul(SB2, _5B), GMul(SB3, _5B));
        BitArray vec2 = XOR4(GMul(SB0, _5B), GMul(SB1, EF), GMul(SB2, EF), SB3);
        BitArray vec3 = XOR4(GMul(SB0, EF), GMul(SB1, _5B), SB2, GMul(SB3, EF));
        BitArray vec4 = XOR4(GMul(SB0, EF), SB1, GMul(SB2, EF), GMul(SB3, _5B));

        //Debug.Log(getIntFromBitArrayInv(modPol(vec1)));
        //Debug.Log(getIntFromBitArrayInv(modPol(vec2)));
        //Debug.Log(getIntFromBitArrayInv(modPol(vec3)));
        //Debug.Log(getIntFromBitArrayInv(modPol(vec4)));
        vec1 = ConvertTo8bitArray(getIntFromBitArrayInv(modPol(vec1)));
        vec2 = ConvertTo8bitArray(getIntFromBitArrayInv(modPol(vec2)));
        vec3 = ConvertTo8bitArray(getIntFromBitArrayInv(modPol(vec3)));
        vec4 = ConvertTo8bitArray(getIntFromBitArrayInv(modPol(vec4)));

        //Debug.Log(ConvertToHex(vec1) + ConvertToHex(vec2) + ConvertToHex(vec3) + ConvertToHex(vec4));

        return AddAppend(AddAppend(AddAppend(vec1, vec2), vec3), vec4);
    }

    /// <summary>
    /// Pojedyńcze przejście rundy z 16
    /// <param name="r1"> 32 bit wejście z porzedniej rundy</param>
    /// <param name="r2"> 32 bit wejście z porzedniej rundy</param>
    /// <param name="r3"> 32 bit wejście z porzedniej rundy</param>
    /// <param name="r4"> 32 bit wejście z porzedniej rundy</param>
    /// <param name="round" >numer rundy</param>
    /// </summary>
    public BitArray[] SingleRound(BitArray r1, BitArray r2, BitArray r3, BitArray r4, int round)
    {
        Debug.Log("1 Runda!");
        //Wyjście z F dla R1 i R2
        BitArray[] F = F_Function(r1, r2,round);
        // >>>>1 (F0 xor R3) 
        BitArray newR1 = ShiftRight(XOR(F[0], r3),1);
        //(<<<<1 R4) xor F1
        BitArray newR2 = XOR(ShiftLft(r4, 1), F[1]);
        //zamiana miejsc R1, R2, R3 i R4
        return new BitArray[] { newR1,newR2,r1,r2 };
    }

    /// <summary>
    /// Pojedyńcze przejście rundy z 16 dla dekrypcji 
    /// <param name="r1"> 32 bit wejście z porzedniej rundy</param>
    /// <param name="r2"> 32 bit wejście z porzedniej rundy</param>
    /// <param name="r3"> 32 bit wejście z porzedniej rundy</param>
    /// <param name="r4"> 32 bit wejście z porzedniej rundy</param>
    /// <param name="round" >numer rundy</param>
    /// </summary>
    public BitArray[] DecryptSingleRound(BitArray r1, BitArray r2, BitArray r3, BitArray r4, int round)
    {
        Debug.Log("1 Runda!");
        //wyjście z F dla R1 i R2
        BitArray[] F = F_Function(r1, r2, round);
        //(<<<<1 R3) xor F0
        BitArray newR1 = XOR( F[0], ShiftLft(r3,1));
        // >>>>1( F1 xor R4)
        BitArray newR2 = ShiftRight(XOR(r4, F[1]),1);
        //zamiana
        return new BitArray[] { newR1, newR2, r1, r2 };
    }

    /// <summary>
    /// Przejście wszystkich etapów 16 rund whitening swap i output whitening
    /// <param name="plainText"> 128 bit tekst do enkrypcji</param>
    /// </summary>
    public BitArray Encrypt(BitArray plainText)
    {
        //input whitening
        BitArray[] wt = InputWhitening(plainText);

        BitArray r1 = wt[0];
        BitArray r2 = wt[1];
        BitArray r3 = wt[2];
        BitArray r4 = wt[3];
        //16 rund
        for (int i = 0; i < 16; i++)
        {
            BitArray[] wn = SingleRound(r1, r2, r3, r4, i);
            r1 = wn[0];
            r2 = wn[1];
            r3 = wn[2];
            r4 = wn[3];
        }
        //undo last swap
        BitArray R1 = r3;
        BitArray R2 = r4;
        BitArray R3 = r1;
        BitArray R4 = r2;

        //output whitening
        BitArray[] otw = OutputWhitening(R1, R2, R3, R4);


        return AddAppend(AddAppend(AddAppend(otw[0], otw[1]), otw[2]), otw[3]);
    }

    /// <summary>
    /// Przejście wszystkich etapów 16 rund whitening swap i output whitening z odwrotnymi kluczami
    /// <param name="plainText"> 128 bit tekst do dekrypcji</param>
    /// </summary>
    public BitArray Decrypt(BitArray cryptetText)
    {
        //input whitening
        BitArray[] wt = InputWhitening(cryptetText);

        BitArray r1 = wt[0];
        BitArray r2 = wt[1];
        BitArray r3 = wt[2];
        BitArray r4 = wt[3];

        for (int i = 0; i < 16; i++)
        {
            //odwrotne klucze 15-i
            BitArray[] wn = DecryptSingleRound(r1, r2, r3, r4, 15-i);
            r1 = wn[0];
            r2 = wn[1];
            r3 = wn[2];
            r4 = wn[3];
        }
        //undo last swap
        BitArray R1 = r3;
        BitArray R2 = r4;
        BitArray R3 = r1;
        BitArray R4 = r2;

        //output whitening
        BitArray[] otw = OutputWhitening(R1, R2, R3, R4);


        return AddAppend(AddAppend(AddAppend(otw[0], otw[1]), otw[2]), otw[3]);
    }

    //poniżej znajdują się funkcje służące komwersji typów

    public string toX(BitArray x)
    {
        byte[] data1 = new byte[100];
        x.CopyTo(data1, 0);
        string hex = BitConverter.ToString(data1);
        return hex;
    }

    /// <summary>
    /// Dopełnienie BitArray do 32 bit
    /// </summary>
    public BitArray FillTo32bit(BitArray a)
    {
        BitArray tor = new BitArray(32);
        int tofill = 32 - a.Length;
        for (int i = 0; i < tofill; i++)
        {
            tor[i] = false;
        }

        for (int i = tofill; i < tor.Length; i++)
        {
            tor[i] = a[i - tofill];
        }
        return tor;
    }

    /// <summary>
    /// int do 4 bit BitArray
    /// </summary>
    public BitArray ConvertTo4bitArray(int n)
    {
        BitArray forbitArray = new BitArray(4);
        for (int i = 0; i < 4; i++)
        {
            forbitArray[i] = (n % 2 == 1);
            n = n / 2;
        }
        return Reverse(forbitArray);
    }

    /// <summary>
    /// int do 8 bit BitArray
    /// </summary>
    public BitArray ConvertTo8bitArray(int n)
    {
        BitArray forbitArray = new BitArray(8);
        for (int i = 0; i < 8; i++)
        {
            forbitArray[i] = (n % 2 == 1);
            n = n / 2;
        }
        return Reverse(forbitArray);
    }

    /// <summary>
    /// reprezentacja operacji ROR
    /// </summary>
    public BitArray ShiftRight(BitArray instance, int n)
    {
        BitArray inst = RemoveFrontZeros(instance);
        if (inst.Length <= 0)
        {
            return instance;
        }
        for (int i = 0; i < n; i++)
        {

            // take out the last element
            bool temp = inst[inst.Length - 1];
            for (int j = inst.Length - 1; j > 0; j--)
            {

                // shift array elements towards right by one place
                inst[j] = inst[j - 1];
            }
            inst[0] = temp;
        }
        return inst;
    }

    /// <summary>
    /// reprezentacja operacji ROL
    /// </summary>
    public BitArray ShiftLft(BitArray instance, int n)
    {
        BitArray inst = RemoveFrontZeros(instance);
        for (int i = 0; i < n; i++)
        {

            // take out the first element
            bool temp = inst[0];
            for (int j = 0; j < inst.Length - 1; j++)
            {

                // shift array elements towards left by 1 place
                inst[j] = inst[j + 1];
            }
            inst[inst.Length - 1] = temp;
        }
        return inst;
    }

    public byte[] ConvertToByte(BitArray bits)
    {
        byte[] ret = new byte[(bits.Length - 1) / 8 + 1];
        bits.CopyTo(ret, 0);
        return ret;
    }

    public static BitArray CopySlice(BitArray source, int offset, int length)
    {
        BitArray ret = new BitArray(length);
        for (int i = 0; i < length; i++)
        {
            ret[i] = source[offset + i];
        }
        return ret;
    }

    /// <summary>
    /// Pomoc do wizualizacji bitów
    /// </summary>
    public string ToBitString(BitArray bits)
    {
        var sb = new StringBuilder();

        for (int i = 0; i < bits.Count; i++)
        {
            char c = bits[i] ? '1' : '0';
            sb.Append(c);
        }

        return sb.ToString();
    }

    public string ByteArrayToString(byte[] ba)
    {
        StringBuilder hex = new StringBuilder(ba.Length * 2);
        foreach (byte b in ba)
            hex.AppendFormat("{0:x2}", b);
        return hex.ToString();
    }

    /// <summary>
    /// Połączenie 2 BitArray w 1
    /// </summary>
    public BitArray AddAppend(BitArray current, BitArray after)
    {
        var bools = new bool[current.Count + after.Count];
        current.CopyTo(bools, 0);
        after.CopyTo(bools, current.Count);
        return new BitArray(bools);
    }

    public static byte[] ShiftLeft(byte[] array, int n)
    {
        var a = array.Select(x => (byte)(x >> 8 - n % 8)).Concat(new byte[(7 + n) / 8]).Select((x, i) => new Tuple<int, byte>(i - (n % 8 == 0 ? 0 : 1), x));
        var b = array.Select(x => (byte)(x << n % 8)).Concat(new byte[n / 8]).Select((x, i) => new Tuple<int, byte>(i, x));

        return (from x in a
                join y in b on x.Item1 equals y.Item1 into yy
                from y in yy.DefaultIfEmpty()
                select (byte)(x.Item2 | (y == null ? 0 : y.Item2))).ToArray();
    }

    public static byte[] ShiftRight(byte[] array, int n)
    {
        return (new byte[n / 8]).Concat(ShiftLeft(array, (8 - (n % 8)) % 8)).ToArray();
    }

    /// <summary>
    /// Zwraca int reprezentujący BitArray (interpretuje od złej strony)
    /// </summary>
    public int getIntFromBitArray(BitArray bitArray)
    {
        int value = 0;
        for (int i = 0; i < bitArray.Length; i++)
        {
            if (bitArray[i])
                value += Convert.ToInt16(Math.Pow(2, i));
        }

        return value;
    }
    /// <summary>
    /// Zwraca int reprezentujący BitArray
    /// </summary>
    public int getIntFromBitArrayInv(BitArray bitArray)
    {
        int value = 0;
        for (int i = 0; i < bitArray.Length; i++)
        {
            if (bitArray[i])
                value += Convert.ToInt16(Math.Pow(2, bitArray.Length-i-1));
        }

        return value;
    }

    private long getLongIntFromBitArray(BitArray bitArray)
    {
        long value = 0;
        for (int i = 0; i < bitArray.Length; i++)
        {
            if (bitArray[i])
                value += Convert.ToInt64(Math.Pow(2, i));
        }

        return value;
    }

    public static byte[] StringToByteArray(String hex)
    {
        int NumberChars = hex.Length;
        byte[] bytes = new byte[NumberChars / 2];
        for (int i = 0; i < NumberChars; i += 2)
            bytes[i / 2] = Convert.ToByte(hex.Substring(i, 2), 16);
        return bytes;
    }

    /// <summary>
    /// zwraca string reprezentujący BitArray w hex
    /// </summary>
    public string ConvertToHex(BitArray bits)
    {
        StringBuilder sb = new StringBuilder(bits.Length / 4);

        for (int i = 0; i < bits.Length; i += 4)
        {
            int v = (bits[i] ? 8 : 0) |
                    (bits[i + 1] ? 4 : 0) |
                    (bits[i + 2] ? 2 : 0) |
                    (bits[i + 3] ? 1 : 0);

            sb.Append(v.ToString("x1")); // Or "X1"
        }

        String result = sb.ToString();
        return result;
    }

    public static string ConvertHex(string hexString)
    {
        try
        {
            string ascii = string.Empty;

            for (int i = 0; i < hexString.Length; i += 2)
            {
                string hs = string.Empty;

                hs = hexString.Substring(i, 2);
                ulong decval = Convert.ToUInt64(hs, 16);
                long deccc = Convert.ToInt64(hs, 16);
                char character = Convert.ToChar(deccc);
                ascii += character;

            }

            return ascii;
        }
        catch (Exception ex) { Console.WriteLine(ex.Message); }

        return string.Empty;
    }

    /// <summary>
    /// reprezentacja operacji XOR
    /// </summary>
    public BitArray XOR(BitArray x, BitArray y)
    {
        BitArray newOne = new BitArray(Math.Max(x.Length,y.Length));
        if (x.Length != newOne.Length)
        {
            BitArray a_prim = new BitArray(newOne.Length);
            for (int i = 0; i < newOne.Length - x.Length; i++)
            {
                a_prim[i] = false;
            }
            for (int i = newOne.Length - x.Length; i < newOne.Length; i++)
            {
                a_prim[i] = x[i - (newOne.Length - x.Length)];
            }
            x = a_prim;
        }

        if (y.Length != newOne.Length)
        {
            BitArray b_prim = new BitArray(newOne.Length);
            for (int i = 0; i < newOne.Length - y.Length; i++)
            {
                b_prim[i] = false;
            }
            for (int i = newOne.Length - y.Length; i < newOne.Length; i++)
            {
                b_prim[i] = y[i - (newOne.Length - y.Length)];
            }
            y = b_prim;
        }

        bool ba = false;
        bool bb = false;

        for (int i = 0; i < newOne.Length; i++)
        {
            //Debug.Log(i);

            ba = x[i];
            bb = y[i];

            newOne[i] = Mxor(ba, bb);
        }
        return newOne;
    }
    /// <summary>
    /// reprezentacja operacji XOR dla 4 wartości
    /// </summary>
    public BitArray XOR4(BitArray a, BitArray b, BitArray c, BitArray d)
    {
        //Debug.Log("4XOR");
        BitArray score = new BitArray(Math.Max(Math.Max(Math.Max(a.Length, b.Length), c.Length), d.Length));

        if (a.Length != score.Length)
        {
            BitArray a_prim = new BitArray(score.Length);
            for (int i =0; i < score.Length - a.Length; i++)
            {
                a_prim[i] = false;
            }
            for(int i = score.Length - a.Length; i< score.Length; i++)
            {
                a_prim[i] = a[i - (score.Length - a.Length)];
            }
            a = a_prim;
        }

        if (b.Length != score.Length)
        {
            BitArray b_prim = new BitArray(score.Length);
            for (int i = 0; i < score.Length - b.Length; i++)
            {
                b_prim[i] = false;
            }
            for (int i = score.Length - b.Length; i < score.Length; i++)
            {
                b_prim[i] = b[i - (score.Length - b.Length)];
            }
            b = b_prim;
        }

        if (c.Length != score.Length)
        {
            BitArray c_prim = new BitArray(score.Length);
            for (int i = 0; i < score.Length - c.Length; i++)
            {
                c_prim[i] = false;
            }
            for (int i = score.Length - c.Length; i < score.Length; i++)
            {
                c_prim[i] = c[i - (score.Length - c.Length)];
            }
            c = c_prim;
        }

        if (d.Length != score.Length)
        {
            BitArray d_prim = new BitArray(score.Length);
            for (int i = 0; i < score.Length - d.Length; i++)
            {
                d_prim[i] = false;
            }
            for (int i = score.Length - d.Length; i < score.Length; i++)
            {
                d_prim[i] = d[i - (score.Length - d.Length)];
            }
            d = d_prim;
        }
        bool ba = false;
        bool bb = false;
        bool bc = false;
        bool bd = false;
        //Debug.Log(score.Length);
        //Debug.Log(a.Length);
        //Debug.Log(b.Length);
        //Debug.Log(c.Length);
        //Debug.Log(d.Length);
        for (int i = 0; i < score.Length; i++)
        {
            //Debug.Log(i);

            ba = a[i];
            bb = b[i];
            bc = c[i];
            bd = d[i];

            score[i] = Mxor(Mxor(Mxor(ba, bb), bc), bd);
        }
        return score;
    }

    /// <summary>
    /// zamiana stringa w hex na BitArray
    /// </summary>
    public static BitArray ConvertHexToBitArray(string hexData)
    {
        if (hexData == null)
            return null; // or do something else, throw, ...

        BitArray ba = new BitArray(4 * hexData.Length);
        for (int i = 0; i < hexData.Length; i++)
        {
            byte b = byte.Parse(hexData[i].ToString(), System.Globalization.NumberStyles.HexNumber);
            for (int j = 0; j < 4; j++)
            {
                ba.Set(i * 4 + j, (b & (1 << (3 - j))) != 0);
            }
        }
        return ba;
    }

    /// <summary>
    /// Funkcja wizualizuje wartość BitArray
    /// </summary>
    public void DebugBits(BitArray array)
    {
        string text = "";
        for (int i = 0; i < array.Length; i++)
        {
            if (array.Get(i))
            {
                text += "1";
            }
            else
            {
                text += "0";
            }
        }
        Debug.Log(text);
    }

    /// <summary>
    /// Wykonanie mnożenia w GF(2^8) z polynomian x^8 x^6 x^5 + x^3 +1
    /// </summary>
    public BitArray GMul(BitArray b, BitArray a)
    {
        BitArray score = new BitArray(a.Length + b.Length-1);
        for (int i=0; i < a.Length; i++)
        {
            for (int j =0; j<b.Length; j++)
            {
                if (a[i])
                {
                    score[i + j] = Mxor(score[i + j], b[j]);
                }
            }
        }
        return modPol(score);
    }

    /// <summary>
    /// Wykonanie mnożenia w GF(2^8) z polynomian x^8 x^6 x^3 +x ^2 +1
    /// </summary>
    public BitArray GMulRS(BitArray b, BitArray a)
    {
        BitArray score = new BitArray(a.Length + b.Length - 1);
        for (int i = 0; i < a.Length; i++)
        {
            for (int j = 0; j < b.Length; j++)
            {
                if (a[i])
                {
                    score[i + j] = Mxor(score[i + j], b[j]);
                }
            }
        }
        return modPolRS(score);
    }

    /// <summary>
    /// Zwykłe mnożenie 
    /// </summary>
    public BitArray MUL_bit(BitArray b, BitArray a)
    {
        BitArray score = new BitArray(a.Length + b.Length - 1);
        for (int i = 0; i < a.Length; i++)
        {
            for (int j = 0; j < b.Length; j++)
            {
                if (a[i])
                {
                    score[i + j] = Mxor(score[i + j], b[j]);
                }
            }
        }
        return score;
    }

    /// <summary>
    /// Odwraca kolejność bitów w BitArray
    /// </summary>
    public BitArray Reverse(BitArray a)
    {
        BitArray rev = new BitArray(a.Length);
        for( int i =0; i<rev.Length; i++)
        {
            rev[i] = a[a.Length - i-1];
        }
        return rev;
    }

    /// <summary>
    /// Zwykłe mnożenie
    /// </summary>
    public BitArray Multiplication(BitArray a, BitArray b)
    {
        int x = getIntFromBitArrayInv(a);
        int y = getIntFromBitArrayInv(b);
        int result = x * y;
        return Reverse(new BitArray( new int[] { result }));
    }

    BitArray polynomian = ConvertHexToBitArray("169"); //x^8 x^6 x^5 + x^3 +1
    BitArray polynomianRS = ConvertHexToBitArray("14D");//x^8 x^6 x^3 +x ^2 +1

    /// <summary>
    /// Wykonanie modulo polynomian x^8 x^6 x^5 + x^3 +1
    /// </summary>
    public BitArray modPol(BitArray x)
    {
        //Debug.Log("ModPol");
        //DebugBits(x);
        BitArray pol = new BitArray(polynomian.Length - 3);
        for (int i = 3; i < polynomian.Length; i++)
        {
            pol[i - 3] = polynomian[i];
        }
        BitArray score = new BitArray(x);
        for(int i=0; i < x.Length -pol.Length+1; i++)
        {
            //DebugBits(score);
            //DebugBits(pol);
            if (score[i])
            {
                if (i == x.Length - pol.Length )
                {
                    if (true)//getIntFromBitArrayInv(score) >= getIntFromBitArrayInv(pol))
                    {
                        //Debug.Log("Ostatni warunek");
                        for (int j = 0; j < pol.Length; j++)
                        {
                            score[j + i] = Mxor(pol[j], score[j + i]);
                        }
                    }
                }
                else
                {
                    for (int j = 0; j < pol.Length; j++)
                    {
                        score[j + i] = Mxor(pol[j], score[j + i]);
                    }
                }
            } 
        }

        return score;
    }

    /// <summary>
    /// Wykonanie modulo polynomian x^8 x^6 x^3 +x ^2 +1
    /// </summary>
    public BitArray modPolRS(BitArray x)
    {
        //Debug.Log("ModPol");
        //DebugBits(x);
        BitArray pol = new BitArray(polynomianRS.Length - 3);
        for (int i = 3; i < polynomianRS.Length; i++)
        {
            pol[i - 3] = polynomianRS[i];
        }
        BitArray score = new BitArray(x);
        for (int i = 0; i < x.Length - pol.Length + 1; i++)
        {
            //DebugBits(score);
            //DebugBits(pol);
            if (score[i])
            {
                if (i == x.Length - pol.Length)
                {
                    if (true)//getIntFromBitArrayInv(score) >= getIntFromBitArrayInv(pol))
                    {
                        //Debug.Log("Ostatni warunek");
                        for (int j = 0; j < pol.Length; j++)
                        {
                            score[j + i] = Mxor(pol[j], score[j + i]);
                        }
                        //DebugBits(score);
                    }
                }
                else
                {
                    for (int j = 0; j < pol.Length; j++)
                    {
                        score[j + i] = Mxor(pol[j], score[j + i]);
                    }
                }
            }
        }
        //DebugBits(score);
        return score;
    }

    /// <summary>
    /// Usuwa zbędne zera z przodu BitArray
    /// </summary>
    public BitArray RemoveFrontZeros(BitArray mod)
    {
        int zeros = 0;
        bool hadTrue = false;
        for (int i = 0; i < mod.Length; i++)
        {
            if (!mod[i] & !hadTrue)
            {
                zeros++;
            }
            else
            {
                hadTrue = true;
            }
        }

        BitArray pol = new BitArray(mod.Length - zeros);
        for (int i = zeros; i < mod.Length; i++)
        {
            pol[i - zeros] = mod[i];
        }
        return pol;
    }
    /// <summary>
    /// x modulo mod
    /// </summary>
    public BitArray MOD_bit(BitArray x, BitArray mod)
    {
        int zeros = 0;
        bool hadTrue = false;
        for (int i = 0; i < mod.Length; i++)
        { 
            if (!mod[i] & !hadTrue)
            {
                zeros++;
            }
            else
            {
                hadTrue = true;
            }
        }

        BitArray pol = new BitArray(mod.Length - zeros);
        for (int i = zeros; i < mod.Length; i++)
        {
            pol[i - zeros] = mod[i];
        }

        BitArray score = new BitArray(x);
        for (int i = 0; i < x.Length - pol.Length + 1; i++)
        {
            //DebugBits(score);
            //DebugBits(pol);
            if (score[i])
            {
                if (i == x.Length - pol.Length)
                {
                    if (true)//getIntFromBitArray(score) >= getIntFromBitArray(pol))
                    {
                        //Debug.Log("Ostatni warunek");
                        for (int j = 0; j < pol.Length; j++)
                        {
                            score[j + i] = Mxor(pol[j], score[j + i]);
                        }
                    }
                }
                else
                {
                    for (int j = 0; j < pol.Length; j++)
                    {
                        score[j + i] = Mxor(pol[j], score[j + i]);
                    }
                }
            }
        }

        return score;
    }

    /// <summary>
    /// XOR na bool
    /// </summary>
    public bool Mxor(bool a, bool b)
    {
        if (a & b)
        {
            return false;
        }else if (a | b)
        {
            return true;
        }
        else
        {
            return false;
        }
    }

}



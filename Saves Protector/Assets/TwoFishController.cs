using System.Collections;
using System.Collections.Generic;
using UnityEngine;
using Crypto;
using System.Text;

public class TwoFishController : MonoBehaviour
{
    private string key = "00000000000000000000000000000000";//"57656C636F6D52054776F46669736820";
    private string text128bit = "000102030405060708090A0B0C0D0E0F";//"54776F46697368206973206E69636520";

    public string StartTwofish(string asset, bool shouldEncrypt)
    {
        TwoFish tf = new TwoFish();
        BitArray bytes = TwoFish.ConvertHexToBitArray(key);
        tf.GenerateKeys(bytes);
        string result = "";
        if (shouldEncrypt)
        {
            result = tf.Encrypt(asset);
        }
        else
        {
            result = tf.Decrypt(asset);
        }
        return result;
    }

    public void test()
    {
        Debug.Log(StartTwofish("dddddddd", true));

        Debug.Log(StartTwofish(StartTwofish("dddddddd", true), false));
    }

    //sprawdzone obliczeniami
    public void q0Test()
    {
        TwoFish tf = new TwoFish();
        var bitArray = TwoFish.ConvertHexToBitArray("52");
        tf.q0(bitArray);
    }
    //sprawdzone obliczeniami 
    public void SboxTest()
    {
        TwoFish tf = new TwoFish();
        //var bytes = Encoding.ASCII.GetBytes("aaaa");
        var bitArray = TwoFish.ConvertHexToBitArray("00000000");

        tf.S_Box(bitArray, TwoFish.ConvertHexToBitArray("07060504"), TwoFish.ConvertHexToBitArray("03020100"));
    }

    public void F_FunctionTest()
    {
        TwoFish tf = new TwoFish();
        tf.F_Function(TwoFish.ConvertHexToBitArray("52C54DDE"), TwoFish.ConvertHexToBitArray("11F0626D"), 1);
    }

    //powinno działać
    public void Test_PHT()
    {
        TwoFish tf = new TwoFish();
        BitArray key8 = TwoFish.ConvertHexToBitArray("F98FFEF9");
        BitArray key9 = TwoFish.ConvertHexToBitArray("9C5B3C17");
        tf.PHT(TwoFish.ConvertHexToBitArray("C06D4949"), TwoFish.ConvertHexToBitArray("41B9BFC1"));//,key8,key9);

    }

    //działa
    public void KeyGeneratorTest()
    {
        TwoFish tf = new TwoFish();
        BitArray bytes = TwoFish.ConvertHexToBitArray("000102030405060708090A0B0C0D0E0F");
        //tf.DebugBits(TwoFish.ConvertHexToBitArray("14D"));
        //tf.ConvertToHex(tf.ConvertTo8bitArray(tf.getIntFromBitArrayInv(tf.GMulRS(TwoFish.ConvertHexToBitArray("0B"), TwoFish.ConvertHexToBitArray("F3")))));
        tf.SKeyGenerator(bytes);
    }

    public void SubKeyGeneratorTest()
    {
        TwoFish tf = new TwoFish();
        BitArray bytes = TwoFish.ConvertHexToBitArray("00000000000000000000000000000000");

        BitArray[] keys= tf.SubkeysKGenerator(0,bytes);
        tf.DebugBits(keys[0]);
    }

    public void G_FunctionTest()
    {
        TwoFish tf = new TwoFish();
        tf.G_function(TwoFish.ConvertHexToBitArray("52C54DDE"), TwoFish.ConvertHexToBitArray("00000000"), TwoFish.ConvertHexToBitArray("00000000"));
    }

    public void H_functionTest()
    {
        TwoFish tf = new TwoFish();
        //var bytes = Encoding.ASCII.GetBytes("aaaa");
        var bitArray = TwoFish.ConvertHexToBitArray("0");

        tf.function_H(bitArray, TwoFish.ConvertHexToBitArray("00010203"), TwoFish.ConvertHexToBitArray("08090A0B"));
        //tf.q1(tf.ConvertTo8bitArray(0));
    }

    public void SingleLoopTest()
    {
        TwoFish tf = new TwoFish();
        tf.GenerateKeys(TwoFish.ConvertHexToBitArray("00000000000000000000000000000000"));
        BitArray[] wt = tf.InputWhitening(TwoFish.ConvertHexToBitArray("00000000000000000000000000000000"));
        BitArray[] wn= tf.SingleRound(wt[0], wt[1], wt[2], wt[3],0);

        tf.DebugBits(wn[0]);
        tf.DebugBits(wn[1]);
        tf.DebugBits(wn[2]);
        tf.DebugBits(wn[3]);
    }

    //tutaj jest enkrypcja i dekrypcja
    public void EncryptTest()
    {
        TwoFish tf = new TwoFish();
        tf.GenerateKeys(TwoFish.ConvertHexToBitArray("00000000000000000000000000000000"));
        BitArray encrypted = tf.Encrypt(TwoFish.ConvertHexToBitArray("00000000000000000000000000000000"));
        tf.DebugBits(encrypted);
        BitArray decrypted = tf.Decrypt(encrypted);
        tf.DebugBits(decrypted);
    }

    //Kilka prowizorycznych testów automatycznych
    public bool Q0_tests()
    {
        TwoFish tf = new TwoFish();
        bool done = true;
        if (tf.ConvertToHex(tf.q0(TwoFish.ConvertHexToBitArray("00"))) != "a9")
        {
            done = false;
        }
        if (tf.ConvertToHex(tf.q0(TwoFish.ConvertHexToBitArray("a1"))) != "f1")
        {
            done = false;
        }
        if (tf.ConvertToHex(tf.q0(TwoFish.ConvertHexToBitArray("1c"))) != "fa")
        {
            done = false;
        }
        if (tf.ConvertToHex(tf.q0(TwoFish.ConvertHexToBitArray("fb"))) != "42")
        {
            done = false;
        }
        if (tf.ConvertToHex(tf.q0(TwoFish.ConvertHexToBitArray("05"))) != "12")
        {
            done = false;
        }
        if (tf.ConvertToHex(tf.q0(TwoFish.ConvertHexToBitArray("01"))) != "a4")
        {
            done = false;
        }

        return done;
    }

    public bool Q1_tests()
    {
        TwoFish tf = new TwoFish();
        bool done = true;
        if (tf.ConvertToHex(tf.q1(TwoFish.ConvertHexToBitArray("00"))) != "15")
        {
            done = false;
        }
        if (tf.ConvertToHex(tf.q1(TwoFish.ConvertHexToBitArray("00"))) != "15")
        {
            done = false;
        }
        if (tf.ConvertToHex(tf.q1(TwoFish.ConvertHexToBitArray("a3"))) != "e2")
        {
            done = false;
        }
        if (tf.ConvertToHex(tf.q1(TwoFish.ConvertHexToBitArray("1e"))) != "06")
        {
            done = false;
        }
        if (tf.ConvertToHex(tf.q1(TwoFish.ConvertHexToBitArray("f1"))) != "af")
        {
            done = false;
        }
        if (tf.ConvertToHex(tf.q1(TwoFish.ConvertHexToBitArray("e0"))) != "22")
        {
            done = false;
        }
        if (tf.ConvertToHex(tf.q1(TwoFish.ConvertHexToBitArray("01"))) != "ea")
        {
            done = false;
        }

        return done;
    }

    public bool HfunctionTests()
    {
        TwoFish tf = new TwoFish();
        bool done = true;

        BitArray[] wynik = tf.function_H(TwoFish.ConvertHexToBitArray("0"), TwoFish.ConvertHexToBitArray("00010203"), TwoFish.ConvertHexToBitArray("08090A0B"));
        if (tf.ConvertToHex(wynik[0]) != "af" | tf.ConvertToHex(wynik[1]) != "42" | tf.ConvertToHex(wynik[2]) != "22"| tf.ConvertToHex(wynik[3]) != "12")
        {
            done = false;
        }
        

        return done;
    }

    public bool MdsTest()
    {
        TwoFish tf = new TwoFish();
        bool done = true;

        BitArray[] wynik = tf.function_H(TwoFish.ConvertHexToBitArray("0"), TwoFish.ConvertHexToBitArray("00010203"), TwoFish.ConvertHexToBitArray("08090A0B"));
        if (tf.ConvertToHex(tf.MDS(wynik[0], wynik[1], wynik[2], wynik[3])) != "5430e6e6")
        {
            done = false;
        }

        return done;
    }

    public bool PhtTest()
    {
        TwoFish tf = new TwoFish();
        bool done = true;

        BitArray[] wynik = tf.function_H(TwoFish.ConvertHexToBitArray("0"), TwoFish.ConvertHexToBitArray("00010203"), TwoFish.ConvertHexToBitArray("08090A0B"));
        BitArray[] wynik1 = tf.function_H(TwoFish.ConvertHexToBitArray("1"), TwoFish.ConvertHexToBitArray("04050607"), TwoFish.ConvertHexToBitArray("0C0D0E0F"));
        BitArray MDS1 = tf.MDS(wynik[0], wynik[1], wynik[2], wynik[3]);
        BitArray MDS2 = tf.MDS(wynik1[0], wynik1[1], wynik1[2], wynik1[3]);
        BitArray ROL8 = tf.ShiftLft(MDS2, 8);
        tf.PHT(MDS1, ROL8);


        return done;
    }

    public bool SKeyTest()
    {
        bool done = true;
        TwoFish tf = new TwoFish();
        BitArray bytes = TwoFish.ConvertHexToBitArray("000102030405060708090A0B0C0D0E0F");
        BitArray[] wynik = tf.SKeyGenerator(bytes);
        //Debug.Log(tf.ConvertToHex(wynik[0]));
        //Debug.Log(tf.ConvertToHex(wynik[1]));
        if (tf.ConvertToHex(wynik[0])!= "2f062ad7" | tf.ConvertToHex(wynik[1])!= "f204791a")
        {
            done = false;
        }
        return done;
    }

    public bool InputWhiteningTest()
    {
        bool done = true;
        TwoFish tf = new TwoFish();
        BitArray wt = tf.InputWhitening(TwoFish.ConvertHexToBitArray("57656c636f6d52054776f46669736820"), TwoFish.ConvertHexToBitArray("54776f46697368206973206e69636520"));
        //Debug.Log(tf.ConvertToHex(wt));
        if (tf.ConvertToHex(wt) != "03120325061e3a252e05d40800100d00")
        {
            done = false;
        }
        return done;
    }

    private void Start()
    {
        if (!Q0_tests())
        {
            Debug.Log("Q0 Failed");
        }
        if (!Q1_tests())
        {
            Debug.Log("Q1 Failed");
        }
        if (!HfunctionTests())
        {
            Debug.Log("H function Failed");
        }
        if (!MdsTest())
        {
            Debug.Log("MDS Failed");
        }
        if (!PhtTest())
        {
            Debug.Log("PHT Failed");
        }
        if (!SKeyTest())
        {
            Debug.Log("S key failed");
        }
        if (!InputWhiteningTest())
        {
            Debug.Log("Whitening failed");
        }
    }


}

using System.Collections;
using System.Collections.Generic;
using UnityEngine;
using Crypto;

public class BlowfishController : MonoBehaviour
{
    private const string key = "8cd91ec74871aaff";

    private string s = "<foo><to>Tove</to><from>Jani</from><heading>Reminder</heading><body>Dont forget me this weekend!</body></foo>";
    private string d = "CEBF8450B11886806EF3830DAA2C2920D1C8FD4AE32DB5316D4DC927C494A854117E7F1086A8CAF5957F69C133C516275AD889EF8DBA2D99362CB6492EBE1607B8E0D551C7CBC06EA99EE1DC3DEE4AAB4F1A9FEBF4366102129C85009F4F481D2B63E0E10BAA9F8BD381F7558FF13D09";
    private BlowFish blowFish;
    public string StartBlowfish(string asset, bool shouldEncrypt)
    {
        string result = "";

        if(blowFish == null)
            blowFish = new BlowFish(key);

        if (shouldEncrypt)
        {
            result = blowFish.Encrypt(asset);
        }
        else
        {
            result = blowFish.Decrypt(asset);
        }
        return result;
    }


    [ContextMenu("BlowfishEncryptTest")]
    public void BlowfishTest()
    {
        string result = "";
        BlowFish blowFish = new BlowFish(key);
        result = blowFish.Encrypt(s);
        Debug.Log(result);
    }

    [ContextMenu("BlowfishDecryptTest")]
    public void BlowfishDTest()
    {
        string result = "";
        BlowFish blowFish = new BlowFish(key);
        result = blowFish.Decrypt(d);
        Debug.Log(result);
    }

}

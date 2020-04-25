using System.Collections;
using System.Collections.Generic;
using UnityEngine;
using Crypto;


public class DESController : MonoBehaviour
{
    private const string key = "133457799BBCDFF1";
    private DES des;
    public string StartDES(string asset, bool shouldEncrypt)
    {
        string result = "";

        if (des == null)
            des = new DES(key);
        if (shouldEncrypt)
            result = des.Encrypt(asset);
        else
            result = des.Decrypt(asset);
        return result;
    }

}

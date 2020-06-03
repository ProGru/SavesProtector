using System.Collections;
using System.Collections.Generic;
using UnityEngine;
using Crypto;


public class DESController : MonoBehaviour
{
    public TextAsset XmlSaveFile;
    public TextAsset JsonSaveFile;
    public TextAsset YamlSaveFile;

    /*private void Start()
    {
        var xmlStringValue = XmlSaveFile.ToString();
        var jsonStringValue = JsonSaveFile.ToString();
        var ymlStringValue = YamlSaveFile.ToString();

        DES des = new DES("133457799BBCDFF1");
        var encrypted = des.Encrypt(ymlStringValue);
        Debug.Log(encrypted);
        var decrypted = des.Decrypt(encrypted);
        Debug.Log(decrypted);
    }*/

}

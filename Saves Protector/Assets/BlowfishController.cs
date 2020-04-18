using System.Collections;
using System.Collections.Generic;
using UnityEngine;
using Crypto;

public class BlowfishController : MonoBehaviour
{
    public TextAsset XmlSaveFile;
    public TextAsset JsonSaveFile;
    public TextAsset YamlSaveFile;
    private void Start()
    {
        var xmlStringValue = XmlSaveFile.ToString();
        var jsonStringValue = JsonSaveFile.ToString();
        var ymlStringValue = YamlSaveFile.ToString();

        BlowFish blowFish = new BlowFish("8cd91ec74871aaff");
        var encrypted = blowFish.Encrypt(ymlStringValue);
        Debug.Log(encrypted);
        var decrypted = blowFish.Decrypt(encrypted);
        Debug.Log(decrypted);
    }
}

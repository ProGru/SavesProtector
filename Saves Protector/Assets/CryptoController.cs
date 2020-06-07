using Newtonsoft.Json;
using System;
using System.Collections;
using System.Collections.Generic;
using System.Text.RegularExpressions;
using System.Xml;
using TMPro;
using UnityEngine;
using UnityEngine.UI;

public class CryptoController : MonoBehaviour
{
    private static int EncryptValue = 0;
    private static int DecryptValue = 1;


    [SerializeField]
    private Button runBtn;

    [SerializeField]
    private Slider algorithmSlider;

    [SerializeField]
    private TMP_InputField inputField;

    [SerializeField]
    private Slider decryptEncryptSlider;

    [SerializeField]
    private BlowfishController blowfishController;

    [SerializeField]
    private DESController desController;

    [SerializeField]
    private TwoFishController twoFishController;

    private void Awake()
    {
        runBtn.onClick.RemoveAllListeners();
    }

    private void OnEnable()
    {
        runBtn.onClick.AddListener(RunAlgorithm);
    }

    private void OnDisable()
    {
        runBtn.onClick.RemoveAllListeners();
    }

    private void RunAlgorithm()
    {
        try
        {
            bool shouldEncrypt = ParseEncryptionSliderValue();
            AlgorithmType algorithm = ParseAlgorithmValue();
            Debug.Log(algorithm);

            string asset = LoadAssetFromPath();

            string result = "";

            if (algorithm == AlgorithmType.BLOWFISH)
            {
                result = blowfishController.StartBlowfish(asset, shouldEncrypt);
            }
            else if (algorithm == AlgorithmType.DES)
            {
                result = desController.StartDES(asset, shouldEncrypt);
            }else if (algorithm == AlgorithmType.TWOFISH)
            {
                result = twoFishController.StartTwofish(asset, shouldEncrypt);
            }

            SaveToFile(shouldEncrypt, result);

        }
        catch (Exception e)
        {
            Debug.LogError(e);
        }
    }

    private void SaveToFile(bool shouldEncrypt, string result)
    {
        var pathWithoutExtension = System.IO.Path.GetDirectoryName(inputField.text);
        var fileName = System.IO.Path.GetFileNameWithoutExtension(inputField.text);

        string resultToWrite = "";
        string extensionString = ".txt";
        FileType fileType = FileType.UNDEFINED;
        if (shouldEncrypt == false)
        {
            extensionString = ParseExtensionToString(result.Substring(0, 3));
            fileType = ParseExtension(extensionString);
            resultToWrite = result.Substring(3);
        }
        else
        {
            resultToWrite = result;
        }

        SaveToProperFormat(pathWithoutExtension, resultToWrite, extensionString, fileName, fileType);
    }

    private void SaveToProperFormat(string pathWithoutExtension, string resultToWrite, string extensionString, string fileName, FileType fileType)
    {
        fileName = fileName + "saveprotector";
        switch (fileType)
        {
            case FileType.JSN:
                System.IO.File.WriteAllText(pathWithoutExtension+fileName+extensionString, resultToWrite);
                break;
            case FileType.XML:
                XmlDocument doc = new XmlDocument();
                doc.LoadXml(resultToWrite);
                XmlWriterSettings settings = new XmlWriterSettings();
                settings.Indent = true;
                XmlWriter writer = XmlWriter.Create(pathWithoutExtension + "\\" + fileName + extensionString, settings);
                doc.Save(writer);
                break;
            case FileType.YML:
                System.IO.File.WriteAllText(pathWithoutExtension + fileName + extensionString, resultToWrite);
                break;
            case FileType.UNDEFINED:
                var path = pathWithoutExtension + "\\" + fileName + ".txt";
                System.IO.File.WriteAllText(path, resultToWrite);
                break;
        }
    }

    private string LoadAssetFromPath()
    {
        var extensionWithDot = System.IO.Path.GetExtension(inputField.text);
        FileType extension = ParseExtension(extensionWithDot);
        return CreateTextAssetFromFile(extension);
    }

    private string CreateTextAssetFromFile(FileType extension)
    {
        string text;
        using (System.IO.StreamReader streamReader = System.IO.File.OpenText(inputField.text))
        {
           text = streamReader.ReadToEnd();
        }

        string value = System.IO.File.ReadAllText(inputField.text, System.Text.Encoding.ASCII);
        value = value.Replace(Environment.NewLine, string.Empty);
        string finalValue = "";

        if (extension == FileType.UNDEFINED)
            finalValue = value;
        else
            finalValue = extension.ToString() + value;

        return finalValue;
    }

    private FileType ParseExtension(string extensionWithDot)
    {
        string extension = extensionWithDot.Substring(1);
        FileType fileType;
        switch (extension)
        {
            case "json":
                fileType = FileType.JSN;
                break;
            case "xml":
                fileType = FileType.XML;
                break;
            case "yml":
            case "yaml":
                fileType = FileType.YML;
                break;
            default:
                fileType = FileType.UNDEFINED;
                break;
        }
        return fileType;
    }

    private string ParseExtensionToString(string ext)
    {
        string extension = "";
        switch (ext)
        {
            case "JSN":
                extension = ".json";
                break;
            case "XML":
                extension = ".xml";
                break;
            case "YML":
            case "YAML":
                extension = ".yml";
                break;
        }
        return extension;
    }

    private AlgorithmType ParseAlgorithmValue()
    {
        Debug.Log(algorithmSlider.value);
        return (AlgorithmType)algorithmSlider.value;
    }

    private bool ParseEncryptionSliderValue()
    {
        if (decryptEncryptSlider.value == DecryptValue)
            return false;
        else if (decryptEncryptSlider.value == EncryptValue)
            return true;
        else
            return false;
    }
}

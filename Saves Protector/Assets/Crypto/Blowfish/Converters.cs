using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Assets.Crypto.Blowfish
{
    public class Converters
    {
        public string ConvertByteToHex(byte[] byteArray)
        {
            var result = BitConverter.ToString(byteArray).Replace("-", string.Empty);
            return result;
        }
        public byte[] ConvertHexToByte(string hex)
        {
            return Enumerable.Range(0, hex.Length)
                             .Where(x => x % 2 == 0)
                             .Select(x => Convert.ToByte(hex.Substring(x, 2), 16))
                             .ToArray();
        }
    }
}

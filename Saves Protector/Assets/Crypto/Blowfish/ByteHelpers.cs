using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Assets.Crypto.Blowfish
{
    public class ByteHelpers
    {
        public byte GetFirstByte(uint w)
        {
            return (byte)(w / 256 / 256 / 256 % 256);
        }
        public byte GetSecondByte(uint w)
        {
            return (byte)(w / 256 / 256 % 256);
        }
        public byte GetThirdByte(uint w)
        {
            return (byte)(w / 256 % 256);
        }
        public byte GetFourthByte(uint w)
        {
            return (byte)(w % 256);
        }
    }
}

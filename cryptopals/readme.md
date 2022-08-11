https://cryptopals.com/sets/1

Ill be using Csharp here.

https://cryptopals.com/sets/1/challenges/1

## COnvert hex to base 64

```C#
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace cryptopals_net
{
    internal class Program
    {
        public static byte[] ConvertFromStringToHex(string inputHex) {
            inputHex = inputHex.Replace("-", "");
            byte[] resultantArray = new byte[inputHex.Length / 2];
            for (int i = 0; i < resultantArray.Length; i++) { 
                resultantArray[i] = Convert.ToByte(inputHex.Substring(i * 2, 2), 16);   
            }
            return resultantArray;
         }

        static void Main(string[] args)
        {
            string hexstr = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
            byte[] data = ConvertFromStringToHex(hexstr);
            string base64 = Convert.ToBase64String(data);

            Console.WriteLine(base64);
            Console.ReadKey();

        }


    }
}

```
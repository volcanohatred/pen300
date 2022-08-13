https://cryptopals.com/sets/1

Ill be using Csharp here.

# https://cryptopals.com/sets/1/challenges

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

## fixed xor

incomplete

```
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

            byte[] resultantArray = new byte[inputHex.Length / 2];
            for (int i = 0; i < resultantArray.Length; i++) { 
                resultantArray[i] = Convert.ToByte(inputHex.Substring(i * 2, 2), 16);   
            }
            return resultantArray;
         }

        public static string StringXor(string string1, string string2)
        {
            int[] resultantArray = new int[string1.Length];
            for (int i = 0; i < string1.Length; i++) {
                resultantArray[i] = string1[i] ^ string2[i];

                Console.WriteLine("resultant array: " + resultantArray[i].ToString());
                Console.WriteLine("UTF32 array: " + char.ConvertFromUtf32(resultantArray[i]));
            }
            string hello = "arre";

            return hello;
            //turn resultantArray;
        }

        public static byte[] ByteArrays(byte[] x, byte[] y)
        {
            var xorData = new byte[x.Length];

            for (var i = 0; i < x.Length; i++)
                xorData[i] = (byte)(x[i] ^ y[i]);

            return xorData;
        }


        static void Main(string[] args)
        {
            string hexstr = "1c0111001f010100061a024b53535009181c";
            byte[] data = ConvertFromStringToHex(hexstr);
            string base64 = Convert.ToBase64String(data);

            string xor_partner_string = "686974207468652062756c6c277320657965";
            byte[] data1 = ConvertFromStringToHex(xor_partner_string);
            string base641 = Convert.ToBase64String(data1);

            byte[] xor_result = ByteArrays(data, data1);
            string xor_64 = Convert.ToBase64String(xor_result);


            Console.WriteLine(base64);
            Console.WriteLine(base641);
            Console.WriteLine(xor_64);
            Console.ReadKey();

        }


    }
}

```
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    /// <summary>
    /// The List<int> is row based. Which means that the key is given in row based manner.
    /// </summary>
    public class HillCipher :  ICryptographicTechnique<List<int>, List<int>>
    {
        public List<int> Analyse(List<int> plainText, List<int> cipherText)
        {
            //throw new NotImplementedException();
           
            for (int fir = 0; fir < 26; fir++)
            {
                for(int second = 0; second < 26; second++)
                {
                    for(int third = 0; third < 26; third++)
                    {
                        for(int fourth = 0; fourth < 26; fourth++)
                        {
                            List<int> key = new List<int>
                            {
                                fir, second, third,fourth
                            };
                            if (Enumerable.SequenceEqual(cipherText, Encrypt(plainText, key)))
                            {
                                return key;
                            }
                        }
                    }
                }
            }
            throw new InvalidAnlysisException();

        }


        public List<int> Decrypt(List<int> cipherText, List<int> key)
        {
            // throw new NotImplementedException();
            int size = key.Count();
            int result = (int)Math.Sqrt(size);
            List<int> DeCypheredText = new List<int>();
            List<int> keyinverse;
            if (key.Count == 4) {
                keyinverse = inverse2(key);
            }
            else
            {
               keyinverse = inverse3(key);
            }
            
            if (result * result != size) throw new Exception("wrong key size");
           
            return Encrypt(cipherText,keyinverse);
        }
        public List<int> inverse2(List<int> key)
        {
            int deter = (key[0] * key[3] - key[1] * key[2]) % 26;
            if (deter < 0) deter += 26;
            int inver = -1;

            for (int x = 1; x < 26; x++)
            {
                if ((deter * x) % 26 == 1)
                {
                    inver = x;
                    break;
                }
            }
            if (inver == -1) throw new InvalidAnlysisException();
            List<int> keyinverse = new List<int>
            {
               (key[3] * inver) % 26,
               (-key[1] * inver + 26) % 26,
               (-key[2] * inver + 26) % 26,
               (key[0] * inver) % 26
             };
            return keyinverse;
        }
        public List<int> inverse3(List<int> Text)
        {
            List<int> inverse = new List<int>();
            int size = Text.Count();
            size = (int)Math.Sqrt((double)size);
           
            int det = (Text[0] * (Text[4] * Text[8] - Text[5] * Text[7]))
                - (Text[1] * (Text[3] * Text[8] - Text[5] * Text[6]))
                +(Text[2] * (Text[3] * Text[7] - Text[4] * Text[6]));
            
            det = ((det % 26) + 26) % 26;
            int inver = -1;

            for (int x = 1; x < 26; x++)
            {
                if ((det * x) % 26 == 1)
                {
                    inver = x;
                    break;
                }
            }
            if (inver == -1) throw new InvalidAnlysisException();
            List<int> adj = new List<int>
             {
                ((Text[4] * Text[8] - Text[5] * Text[7]) % 26 + 26) % 26,
                ((-1 * (Text[1] * Text[8] - Text[2] * Text[7])) % 26 + 26) % 26,
                ((Text[1] * Text[5] - Text[2] * Text[4]) % 26 + 26) % 26,
                ((-1 * (Text[3] * Text[8] - Text[5] * Text[6])) % 26 + 26) % 26,
                ((Text[0] * Text[8] - Text[2] * Text[6]) % 26 + 26) % 26,
                ((-1 * (Text[0] * Text[5] - Text[2] * Text[3])) % 26 + 26) % 26,
                ((Text[3] * Text[7] - Text[4] * Text[6]) % 26 + 26) % 26,
                ((-1 * (Text[0] * Text[7] - Text[1] * Text[6])) % 26 + 26) % 26,
                ((Text[0] * Text[4] - Text[1] * Text[3]) % 26 + 26) % 26

             };
            for (int i = 0; i < 9; i++)
            {
                int x = (adj[i]*inver) % 26;
                if (x < 0) x += 26;
                inverse.Add( x);
            }
         
            return inverse;
        }

        public List<int> Encrypt(List<int> plainText, List<int> key)
        {
            // throw new NotImplementedException();
           int size= key.Count();
            int result = (int)Math.Sqrt((double)size);
            List<int> CypheredText= new List<int>();
            int sum = 0;
            for(int i=0; i < plainText.Count(); i+=result)
            {
                for (int r = 0; r < result; r++)
                {
                    sum = 0;
                    for(int c = 0;c<result; c++)
                    {
                        sum += key[r*result+c]*plainText[i+c];
                    }

                    CypheredText.Add((sum % 26 + 26) % 26);
                }
            }
            return CypheredText;
        }


        public List<int> Analyse3By3Key(List<int> plainText, List<int> cipherText)
        {
            //throw new NotImplementedException();
            List<int> inverseplainText =inverse3(plainText);
            List<int> key = new List<int>(new int[9]);
           // Console.WriteLine("Inverse Matrix: " + string.Join(", ", inverseplainText));

          
            for (int row = 0; row < 3; row++)
            {
                for (int col = 0; col < 3; col++)
                {
                    int sum = 0;

                    for (int k = 0; k < 3; k++)
                    {
                        int mul = inverseplainText[row * 3 + k] * cipherText[k * 3 + col];
                       // Console.WriteLine($"Multiplying: {inverseplainText[row * 3 + k]} * {cipherText[k * 3 + col]} = {mul}");
                        sum += mul;
                    }

                    key[col * 3 + row] = (sum % 26);
                    if (key[row * 3 + col] < 0)
                        key[row * 3 + col] += 26;
                  //  Console.WriteLine($" Key[{row},{col}]: {sum}");
                   // Console.WriteLine($" Key[{row},{col}]: {key[row * 3 + col]}");
                }
            }
          
           // Console.WriteLine("Inverse Matrix: " + string.Join(", ", key));
            return key;
        }

    }
}

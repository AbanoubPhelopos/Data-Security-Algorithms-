using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class Columnar : ICryptographicTechnique<string, List<int>>
    {
        public List<int> Analyse(string plainText, string cipherText)
        {
            /*
                - The Difference Between Two Consecutive Letters represent the key length 
                       0 1 2 3 4 5 6 7 8 9 10 11 12 13 14
                       c o m p u t e r s c i  e  n  c  e     
                       _     ^   _     ^
                - So Implement The PlainText Matrix
            */
            cipherText = cipherText.ToLower();
            plainText = plainText.ToLower();
            int colsCnt = 1, rowsCnt = 0, idx = 0, cnt = 0, colNum = 1, curIdx = 0;
            bool isCorrect = false, stop = false;
            char[,] plainTextMatrix;
            int[] key;

            for (; !stop; colsCnt++)
            {
                rowsCnt = (int)Math.Ceiling((float)plainText.Length / colsCnt);
                for (int i = 0; i < rowsCnt - 2; i++)
                {
                    isCorrect = false;
                    for (int j = 0; j < plainText.Length - colsCnt; j++)
                    {
                        if ((plainText[j] == cipherText[i] && plainText[j + colsCnt] == cipherText[i + 1]))
                        {
                            isCorrect = true;
                            break;
                        }
                    }
                    if (i == rowsCnt - 3) stop = true;
                    if (!isCorrect) break;
                }
            }
            colsCnt--;
            key = new int[colsCnt];
            plainTextMatrix = new char[rowsCnt, colsCnt];

            for (int i = 0; i < rowsCnt; i++)
            {
                for (int j = 0; j < colsCnt; j++)
                {
                    plainTextMatrix[i, j] = plainText[idx];
                    idx++;
                    if (idx >= plainText.Length) break;
                }
            }

            idx = 0;
            for (int i = 0; i < colsCnt; i++)
            {
                for (int j = 0; j < Math.Min(rowsCnt, plainText.Length - idx); j++)
                {
                    if (plainTextMatrix[j, i] != cipherText[curIdx]) break;
                    cnt++;
                    curIdx++;
                }
                if (cnt >= rowsCnt - 1)
                {
                    key[i] = colNum;
                    colNum++;
                    idx = curIdx;
                    i = -1; // Start From First Column again ...
                }
                else
                {
                    curIdx = idx;
                }
                cnt = 0;
            }
            return key.ToList();
        }

        public string Decrypt(string cipherText, List<int> key)
        {
            int colsCnt = key.Count, rowsCnt = cipherText.Length / colsCnt, idx = 0;
            int[] colsPositions = new int[colsCnt];
            StringBuilder plainText = new StringBuilder(cipherText.Length);
            char[,] plainTextMatrix = new char[rowsCnt, colsCnt];

            /*=========== Get Actual Columns (Mapping) ===========*/
            for (int i = 0; i < colsCnt; i++)
            {
                colsPositions[key[i] - 1] = i;
            }

            /*=========== Convert Cipher Text To Matrix ===========*/
            for (int i = 0; i < colsCnt; i++)
            {
                for (int j = 0; j < rowsCnt; j++)
                {
                    plainTextMatrix[j, colsPositions[i]] = cipherText[idx];
                    idx++;
                }
            }

            /*=========== Read Matrix Row By Row (Convert Cipher Text to Plain Text) ===========*/
            for (int i = 0; i < rowsCnt; i++)
            {
                for (int j = 0; j < colsCnt; j++)
                {
                    plainText.Append(plainTextMatrix[i, j]);
                }
            }

            return plainText.ToString().ToLower();
        }

        public string Encrypt(string plainText, List<int> key)
        {
            int colsCnt = key.Count, actualColIdx;
            int[] colsPositions = new int[colsCnt];
            StringBuilder cipherText = new StringBuilder(plainText.Length);

            /*=========== Remove The Whitespaces ===========*/
            plainText = plainText.Replace(" ", "");

            /*=========== Get Actual Columns (Mapping) ===========*/
            for (int i = 0; i < colsCnt; i++)
            {
                colsPositions[key[i] - 1] = i;
            }

            /*=========== Extend Plain Text To Fill All Cells ===========*/
            int emptyCellsCnt = (colsCnt - (plainText.Length % colsCnt)) % colsCnt;
            while (emptyCellsCnt > 0)
            {
                emptyCellsCnt--;
                plainText += 'x';
            }

            /*=========== Encryption ===========*/
            for (int i = 0; i < colsCnt; i++)
            {
                actualColIdx = colsPositions[i];
                for (int j = 0; j < Math.Ceiling((float)plainText.Length / colsCnt); j++)
                {
                    cipherText.Append(plainText[actualColIdx + (colsCnt * j)]);
                }
            }
            return cipherText.ToString().ToUpper();
        }
    }
}

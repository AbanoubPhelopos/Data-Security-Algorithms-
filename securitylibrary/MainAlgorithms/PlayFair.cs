using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class PlayFair : ICryptographic_Technique<string, string>
    {
        public string Decrypt(string cipherText, string key)
        {
            char[,] matrix = ConstructMatrix(key);
            List<string> blocks = PrepareCiphertextBlocks(cipherText);
            string plainText = "";

            foreach (string pair in blocks)
            {
                (int row1, int col1) = FindPosition(matrix, pair[0]);
                (int row2, int col2) = FindPosition(matrix, pair[1]);

                if (col1 == col2)
                {
                    plainText += matrix[(row1 + 4) % 5, col1];
                    plainText += matrix[(row2 + 4) % 5, col2];
                }
                else if (row1 == row2)
                {
                    plainText += matrix[row1, (col1 + 4) % 5];
                    plainText += matrix[row2, (col2 + 4) % 5];
                }
                else
                {
                    plainText += matrix[row1, col2];
                    plainText += matrix[row2, col1];
                }
            }

            // X removal logic
            StringBuilder cleanedPlainText = new StringBuilder();

            for (int i = 0; i < plainText.Length; i++)
            {
                if (plainText[i] == 'X')
                {
                    if (i > 0 && i < plainText.Length - 1 &&
                        plainText[i - 1] == plainText[i + 1] &&
                        i % 2 == 1)
                    {
                        continue;
                    }
                }
                cleanedPlainText.Append(plainText[i]);
            }

            if (cleanedPlainText.Length > 0 &&
                cleanedPlainText[cleanedPlainText.Length - 1] == 'X' &&
                cleanedPlainText.Length % 2 == 0)
            {
                cleanedPlainText.Remove(cleanedPlainText.Length - 1, 1);
            }

            // Remove X if it's the last character and its position is even
            if (cleanedPlainText.Length > 0 &&
                cleanedPlainText[cleanedPlainText.Length - 1] == 'X' &&
                (cleanedPlainText.Length - 1) % 2 == 0)
            {
                cleanedPlainText.Remove(cleanedPlainText.Length - 1, 1);
            }

            return cleanedPlainText.ToString();
        }

        public string Encrypt(string plainText, string key)
        {
            char[,] matrix = ConstructMatrix(key);
            List<string> blocks = PreparePlaintextBlocks(plainText);
            string cipherText = "";

            foreach (string pair in blocks)
            {
                (int row1, int col1) = FindPosition(matrix, pair[0]);
                (int row2, int col2) = FindPosition(matrix, pair[1]);

                if (col1 == col2)
                {
                    cipherText += matrix[(row1 + 1) % 5, col1];
                    cipherText += matrix[(row2 + 1) % 5, col2];
                }
                else if (row1 == row2)
                {
                    cipherText += matrix[row1, (col1 + 1) % 5];
                    cipherText += matrix[row2, (col2 + 1) % 5];
                }
                else
                {
                    cipherText += matrix[row1, col2];
                    cipherText += matrix[row2, col1];
                }
            }
            return cipherText;
        }


        //******************************************** Construction *****************************************************************************

        static char[,] ConstructMatrix(string key)
        {
            HashSet<char> usedChars = new HashSet<char>();
            List<char> matrixList = new List<char>();
            bool firstOccurrenceIsI = true;

            key = key.ToUpper().Replace(" ", "");

            foreach (char c in key)
            {
                char letter = c;
                if (letter == 'I' || letter == 'J')
                {
                    if (!usedChars.Contains('I') && !usedChars.Contains('J'))
                    {
                        firstOccurrenceIsI = (letter == 'I');
                    }

                    letter = firstOccurrenceIsI ? 'I' : 'J';
                }

                if (char.IsLetter(letter) && !usedChars.Contains(letter))
                {
                    usedChars.Add(letter);
                    matrixList.Add(letter);
                }
            }

            foreach (char c in "ABCDEFGHIKLMNOPQRSTUVWXYZ")
            {
                if (!usedChars.Contains(c))
                {
                    usedChars.Add(c);
                    matrixList.Add(c);
                }
            }

            char[,] matrix = new char[5, 5];
            for (int i = 0, index = 0; i < 5; i++)
            {
                for (int j = 0; j < 5; j++)
                {
                    matrix[i, j] = matrixList[index++];
                }
            }

            return matrix;
        }

        static List<string> PrepareCiphertextBlocks(string plaintext)
        {
            plaintext = plaintext.ToUpper().Replace(" ", "");
            List<char> processedText = new List<char>();
            bool firstOccurrenceIsI = true;
            HashSet<char> seenIJ = new HashSet<char>();

            foreach (char c in plaintext)
            {
                char letter = c;
                if (letter == 'I' || letter == 'J')
                {
                    if (!seenIJ.Contains('I') && !seenIJ.Contains('J'))
                    {
                        firstOccurrenceIsI = (letter == 'I');
                    }
                    letter = firstOccurrenceIsI ? 'I' : 'J';
                    seenIJ.Add(letter);
                }

                if (char.IsLetter(letter))
                {
                    processedText.Add(letter);
                }
            }

            List<string> blocks = new List<string>();
            for (int i = 0; i < processedText.Count; i++)
            {
                char first = processedText[i];
                char second = (i + 1 < processedText.Count) ? processedText[i + 1] : 'X';

                if (first == second)
                {
                    blocks.Add(first.ToString() + 'X');
                }
                else
                {
                    blocks.Add(first.ToString() + second);
                    i++;
                }
            }

            if (blocks.Count > 0 && blocks[blocks.Count - 1].Length == 1)
            {
                blocks[blocks.Count - 1] += "X";
            }

            return blocks;
        }

        static List<string> PreparePlaintextBlocks(string plaintext)
        {
            plaintext = plaintext.ToUpper().Replace(" ", "");
            List<char> processedText = new List<char>();
            bool firstOccurrenceIsI = true;
            HashSet<char> seenIJ = new HashSet<char>();

            foreach (char c in plaintext)
            {
                char letter = c;
                if (letter == 'I' || letter == 'J')
                {
                    if (!seenIJ.Contains('I') && !seenIJ.Contains('J'))
                    {
                        firstOccurrenceIsI = (letter == 'I');
                    }

                    letter = firstOccurrenceIsI ? 'I' : 'J';
                    seenIJ.Add(letter);
                }

                if (char.IsLetter(letter))
                {
                    processedText.Add(letter);
                }
            }

            List<string> blocks = new List<string>();
            for (int i = 0; i < processedText.Count; i++)
            {
                char first = processedText[i];
                char second = (i + 1 < processedText.Count) ? processedText[i + 1] : 'X';

                if (first == second)
                {
                    blocks.Add(first.ToString() + 'X');
                }
                else
                {
                    blocks.Add(first.ToString() + second);
                    i++;
                }
            }

            if (blocks.Count > 0 && blocks[blocks.Count - 1].Length == 1)
            {
                blocks[blocks.Count - 1] += "X";
            }

            return blocks;
        }


        //************************************************  Helpers ******************************************************************************

        // Helper method used to check on the constructed matrix 
        static void PrintMatrix(char[,] matrix)
        {
            for (int i = 0; i < 5; i++)
            {
                for (int j = 0; j < 5; j++)
                {
                    Console.Write(matrix[i, j] + " ");
                }
                Console.WriteLine();
            }
        }


        // Helper method that searches for a letter in a matrix and returns its position as indices of row and column
        static (int, int) FindPosition(char[,] matrix, char letter)
        {
            for (int i = 0; i < 5; i++)
            {
                for (int j = 0; j < 5; j++)
                {
                    if (matrix[i, j] == letter)
                        return (i, j);
                }
            }
            return (-1, -1);
        }

        public string Analyse(string largeCipher)
        {
            throw new NotImplementedException();
        }
    }
}

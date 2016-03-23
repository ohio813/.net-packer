using managedcrypter.USG;
using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace managedcrypter
{
    public static class Utils
    {
        private static Random Rand = new Random();
        private static char[] Chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz".ToCharArray();

        public static string GenerateRandomString(int len)
        {
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < len; i++)
                sb.Append(Chars[Rand.Next(0, Chars.Length)]);
            return sb.ToString();
        }

        public static string GenerateRandomString(int min, int max)
        {
            int len = Rand.Next(min, max);
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < len; i++)
                sb.Append(Chars[Rand.Next(0, Chars.Length)]);
            return sb.ToString();
        }

        public static void ReplaceStringInFile(string filePath, string strToReplace, string strReplaceWith)
        {
            File.WriteAllText(filePath, File.ReadAllText(filePath).Replace(strToReplace, strReplaceWith));
        }

        public static void ReplaceJunkInSource(string filePath)
        {
            StringBuilder sb = new StringBuilder();
            MethodGen mtdGen = new MethodGen();

            string[] fileSource = File.ReadAllLines(filePath);

            for (int i = 0; i < fileSource.Length; i++)
            {
                if (fileSource[i].Contains(StringConstants.STR_JUNK))
                {
                    for (int x = 0; x < Rand.Next(10, 20); x++)
                        sb.AppendLine(mtdGen.RandMethod());

                    fileSource[i] = sb.ToString();

                    sb = new StringBuilder();
                }
            }

            File.WriteAllLines(filePath, fileSource);
        }

    }
}

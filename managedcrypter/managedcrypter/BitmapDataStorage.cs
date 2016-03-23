namespace managedcrypter
{
    /*
   * Convert binary data to bitmap and vice versa
   * Copyright (C) 2012 0xDEADDEAD
   * Removal of this copyright is prohibited
   */

    using System;
    using System.Drawing;
    using System.Drawing.Imaging;

    public static class BitmapDataStorage
    {
        public static Bitmap CreateBitmapFromData(byte[] binaryData)
        {
            // calc padding amount
            int paddedSize = binaryData.Length + (3 - binaryData.Length % 3) + 6;
            int pixelCount = paddedSize / 3;

            int countPerRow = (int)Math.Ceiling(Math.Sqrt(pixelCount));

            Bitmap bmp = new Bitmap(countPerRow, countPerRow, PixelFormat.Format24bppRgb);

            byte[] paddedData = new byte[paddedSize];
            Buffer.BlockCopy(BitConverter.GetBytes(binaryData.Length), 0, paddedData, 0, 4);
            Buffer.BlockCopy(binaryData, 0, paddedData, 4, binaryData.Length);

            int columnIndex = 0;
            int rowNumber = bmp.Height - 1;
            for (int i = 0; i < pixelCount; i++)
            {
                if (columnIndex == countPerRow)
                {
                    columnIndex = 0;
                    rowNumber--;
                }

                Color pixelColor = Color.FromArgb(
                paddedData[i * 3 + 2],
                paddedData[i * 3 + 1],
                paddedData[i * 3]);
                bmp.SetPixel(columnIndex, rowNumber, pixelColor);
                columnIndex++;

            }
            return bmp;
        }

        public static byte[] ReadDataFromBitmap(Bitmap bitmap)
        {
            byte[] buffer = new byte[bitmap.Width * bitmap.Height * 3];

            int i = 0;
            for (int y = bitmap.Height - 1; y >= 0; y--)
            {
                for (int x = 0; x < bitmap.Width; x++)
                {
                    Color pixelColor = bitmap.GetPixel(x, y);
                    buffer[i * 3 + 2] = pixelColor.R;
                    buffer[i * 3 + 1] = pixelColor.G;
                    buffer[i * 3] = pixelColor.B;
                    i++;
                }
            }

            byte[] data = new byte[BitConverter.ToInt32(buffer, 0)];
            Buffer.BlockCopy(buffer, 4, data, 0, data.Length);
            return data;
        }
    }
}
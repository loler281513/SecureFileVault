using System;
using System.IO;
using System.Security.Cryptography;
using System.Threading.Tasks;

namespace Secure_file_vault
{
    public class SecureDeleteService
    {
        private static readonly RandomNumberGenerator _rng = RandomNumberGenerator.Create();

        public async Task SecureDeleteAsync(string filePath, int passes = 3)
        {
            if (!File.Exists(filePath))
                return;

            try
            {
                var fileInfo = new FileInfo(filePath);
                long fileSize = fileInfo.Length;

                for (int pass = 0; pass < passes; pass++)
                {
                    await OverwriteWithRandomDataAsync(filePath, fileSize);
                }

                await OverwriteWithZerosAsync(filePath, fileSize);

                string tempPath = filePath + ".deleting_" + Guid.NewGuid().ToString();
                File.Move(filePath, tempPath);

                File.SetAttributes(tempPath, FileAttributes.Normal);
                File.Delete(tempPath);
            }
            catch (Exception ex)
            {
                throw new Exception($"Ошибка при безопасном удалении: {ex.Message}");
            }
        }

        private async Task OverwriteWithRandomDataAsync(string filePath, long fileSize)
        {
            byte[] randomData = new byte[65536]; 

            using (var fs = new FileStream(filePath, FileMode.Open, FileAccess.Write,
                   FileShare.None, 65536, useAsync: true))
            {
                fs.Position = 0;
                long bytesRemaining = fileSize;

                while (bytesRemaining > 0)
                {
                    int bytesToWrite = (int)Math.Min(randomData.Length, bytesRemaining);
                    _rng.GetBytes(randomData, 0, bytesToWrite);
                    await fs.WriteAsync(randomData, 0, bytesToWrite);
                    bytesRemaining -= bytesToWrite;
                }

                await fs.FlushAsync();
            }
        }

        private async Task OverwriteWithZerosAsync(string filePath, long fileSize)
        {
            byte[] zeros = new byte[65536];

            using (var fs = new FileStream(filePath, FileMode.Open, FileAccess.Write,
                   FileShare.None, 65536, useAsync: true))
            {
                fs.Position = 0;
                long bytesRemaining = fileSize;

                while (bytesRemaining > 0)
                {
                    int bytesToWrite = (int)Math.Min(zeros.Length, bytesRemaining);
                    await fs.WriteAsync(zeros, 0, bytesToWrite);
                    bytesRemaining -= bytesToWrite;
                }

                await fs.FlushAsync();
            }
        }
    }
}
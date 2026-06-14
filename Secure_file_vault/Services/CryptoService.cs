using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.Cryptography;
using System.Threading.Tasks;

namespace Secure_file_vault.Services
{
    public class CryptoService : IDisposable
    {
        private const int KeySizeInBytes = 32; // 256 бит
        public const int IvSizeInBytes = 12;
        public const int SaltSizeInBytes = 16;

        public byte[] GenerateRandomIv() => GenerateRandomBytes(IvSizeInBytes);
        public byte[] GenerateRandomSalt() => GenerateRandomBytes(SaltSizeInBytes);


        public byte[] DeriveKeyFromSecureString(SecureString password, byte[] salt, int iterations)
        {
            byte[] passwordBytes = SecureStringToByteArray(password);
            try
            {
                using (var pbkdf2 = new Rfc2898DeriveBytes(passwordBytes, salt, iterations, HashAlgorithmName.SHA256))
                {
                    return pbkdf2.GetBytes(KeySizeInBytes);
                }
            }
            finally
            {
                Array.Clear(passwordBytes, 0, passwordBytes.Length);
            }
        }

        private byte[] SecureStringToByteArray(SecureString secureString)
        {
            if (secureString == null)
                throw new ArgumentNullException(nameof(secureString));

            int length = secureString.Length;
            byte[] bytes = new byte[length * 2]; // UTF-16 

            IntPtr ptr = Marshal.SecureStringToGlobalAllocUnicode(secureString);
            try
            {
                Marshal.Copy(ptr, bytes, 0, bytes.Length);
                return bytes;
            }
            finally
            {
                Marshal.ZeroFreeGlobalAllocUnicode(ptr);
            }
        }

        // создание верификатора
        public byte[] CreateMasterKeyVerifier(byte[] masterKey)
        {
            using (var hmac = new HMACSHA256(masterKey))
            {
                
                return hmac.ComputeHash(Array.Empty<byte>());
            }
        }

        public bool VerifyMasterKey(byte[] masterKey, byte[] verifier)
        {
            byte[] computedVerifier = CreateMasterKeyVerifier(masterKey);
            return CryptographicOperations.FixedTimeEquals(computedVerifier, verifier);
        }


        public async Task<byte[]> EncryptFileToFileAsync(string inputPath, string outputPath, byte[] key, byte[] iv)
        {
            using (var aes = new AesGcm(key))
            {
                byte[] plaintext = await File.ReadAllBytesAsync(inputPath);
                byte[] ciphertext = new byte[plaintext.Length];
                byte[] tag = new byte[AesGcm.TagByteSizes.MaxSize];

                aes.Encrypt(iv, plaintext, ciphertext, tag);
                await File.WriteAllBytesAsync(outputPath, ciphertext);
                return tag;
            }
        }

        public async Task<byte[]> DecryptFileAsync(string inputPath, byte[] key, byte[] iv, byte[] tag)
        {
            using (var aes = new AesGcm(key))
            {
                byte[] ciphertext = await File.ReadAllBytesAsync(inputPath);
                byte[] plaintext = new byte[ciphertext.Length];

                aes.Decrypt(iv, ciphertext, tag, plaintext);
                return plaintext;
            }
        }

        public byte[] GenerateRandomBytes(int size)
        {
            return RandomNumberGenerator.GetBytes(size);

        }

        public async Task<bool> VerifyIntegrity(string encryptedFilePath, byte[] key, byte[] iv, byte[] tag)
        {
            try
            {
                await DecryptFileAsync(encryptedFilePath, key, iv, tag);
                return true;
            }
            catch (CryptographicException)
            {
                return false;
            }
        }

        public void Dispose()
        {
            GC.Collect();
            GC.WaitForPendingFinalizers();
        }
    }
}
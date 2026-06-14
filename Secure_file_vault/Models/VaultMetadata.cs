using System.Collections.Generic;

namespace Secure_file_vault.Models
{
    public class VaultMetadata
    {
        public string Version { get; set; } = "1.0";
        public List<FileMetadata> Files { get; set; } = new List<FileMetadata>();
        public int Pbkdf2Iterations { get; set; } = 100000;

        // ключ
        public byte[] MasterKeySalt { get; set; }
        public byte[] MasterKeyVerifier { get; set; }
    }
}
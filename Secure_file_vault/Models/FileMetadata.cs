using System;

namespace Secure_file_vault.Models
{
    public class FileMetadata
    {
        public string Id { get; set; } = Guid.NewGuid().ToString();
        public string OriginalFileName { get; set; }
        public string EncryptedFileName { get; set; }
        public byte[] Iv { get; set; }
        public byte[] Tag { get; set; }
        public DateTime AddedDate { get; set; }
        public long OriginalFileSize { get; set; }
    }
}
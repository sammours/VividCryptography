namespace VividCryptography
{
    using System;
    using System.IO;
    using System.Security.Cryptography;
    using System.Text;

    /// <summary>
    /// Encrypt and Decrypt texts
    /// </summary>
    public class VividCryptography
    {
        private readonly string key;

        /// <summary>
        /// Initial VividCryptography
        /// </summary>
        /// <param name="key">Encryption/Decryption key 64Byte</param>
        public VividCryptography(string key)
        {
            this.key = key;
        }

        /// <summary>
        /// Encrypt
        /// </summary>
        /// <param name="clearText">Origin text</param>
        /// <returns>Encrypted text</returns>
        public string Encrypt(string clearText)
        {
            byte[] clearBytes = Encoding.Unicode.GetBytes(clearText);
            using (var encryptor = Aes.Create())
            {
                byte[] iV = new byte[15];
                var rand = new Random();
                rand.NextBytes(iV);
                var pdb = new Rfc2898DeriveBytes(this.key, iV);
                encryptor.Key = pdb.GetBytes(32);
                encryptor.IV = pdb.GetBytes(16);
                using (var ms = new MemoryStream())
                {
                    using (var cs = new CryptoStream(ms, encryptor.CreateEncryptor(), CryptoStreamMode.Write))
                    {
                        cs.Write(clearBytes, 0, clearBytes.Length);
                    }

                    clearText = Convert.ToBase64String(iV) + Convert.ToBase64String(ms.ToArray());
                }
            }

            return clearText;
        }

        /// <summary>
        /// Decrypt
        /// </summary>
        /// <param name="cipherText">Cipher text</param>
        /// <returns>Origin text</returns>
        public string Decrypt(string cipherText)
        {
            byte[] iV = Convert.FromBase64String(cipherText.Substring(0, 20));
            cipherText = cipherText.Substring(20).Replace(" ", "+");
            byte[] cipherBytes = Convert.FromBase64String(cipherText);
            using (var encryptor = Aes.Create())
            {
                var pdb = new Rfc2898DeriveBytes(this.key, iV);
                encryptor.Key = pdb.GetBytes(32);
                encryptor.IV = pdb.GetBytes(16);
                using (var ms = new MemoryStream())
                {
                    using (var cs = new CryptoStream(ms, encryptor.CreateDecryptor(), CryptoStreamMode.Write))
                    {
                        cs.Write(cipherBytes, 0, cipherBytes.Length);
                    }

                    cipherText = Encoding.Unicode.GetString(ms.ToArray());
                }
            }

            return cipherText;
        }
    }
}

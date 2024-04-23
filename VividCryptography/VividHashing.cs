namespace VividCryptography
{
    using System;
    using System.Security.Cryptography;

    /// <summary>
    /// Generate and compare hashing
    /// </summary>
    public class VividHashing
    {
        private readonly int hashSize;

        private readonly int saltSize;

        private readonly int iterations;

        /// <summary>
        /// Initial VividHashing with default values
        /// hashSize = 256
        /// saltSize = 32 
        /// interation = 10000
        /// </summary>
        public VividHashing()
        {
            this.hashSize = 256;
            this.saltSize = 32;
            this.iterations = 10000;
        }

        /// <summary>
        /// Initial VividHashing with custom values
        /// </summary>
        /// <param name="hashSize">Hash size</param>
        /// <param name="saltSize">Salt size</param>
        /// <param name="iterations">number of iteration</param>
        public VividHashing(int hashSize, int saltSize, int iterations)
        {
            this.hashSize = hashSize;
            this.saltSize = saltSize;
            this.iterations = iterations;
        }

        /// <summary>
        /// Get hash value
        /// </summary>
        /// <param name="plainText">Origin text</param>
        /// <param name="salt">Salt</param>
        /// <returns>Hashed value</returns>
        public string GetCipherText(string plainText, byte[] salt)
            => BitConverter.ToString(this.GetPbkdf2Bytes(plainText, salt, this.hashSize)).Replace("-", string.Empty);

        /// <summary>
        /// Get Salt
        /// </summary>
        /// <returns>Random salt</returns>
        public byte[] GetSalt()
        {
            using (var cryptoProvider = new RNGCryptoServiceProvider())
            {
                byte[] salt = new byte[this.saltSize];
                cryptoProvider.GetBytes(salt);
                return salt;
            }
        }

        /// <summary>
        /// Compare hash
        /// </summary>
        /// <param name="plainText">Origin text</param>
        /// <param name="oldHash">Old hash</param>
        /// <param name="salt">Salt used with the old hash</param>
        /// <returns>True when the the plaintext is the same as origin text</returns>
        public bool CompareHash(string plainText, string oldHash, byte[] salt)
        {
            var hash = this.GetPbkdf2Bytes(plainText, salt, this.hashSize);
            return BitConverter.ToString(hash).Replace("-", string.Empty).Equals(oldHash, StringComparison.OrdinalIgnoreCase);
        }

        private byte[] GetPbkdf2Bytes(string plainText, byte[] salt, int outputBytes)
        {
            using (var pbkdf2 = new Rfc2898DeriveBytes(plainText, salt))
            {
                pbkdf2.IterationCount = this.iterations;
                return pbkdf2.GetBytes(outputBytes);
            }
        }
    }
}

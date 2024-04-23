namespace UnitTest
{
    using Microsoft.VisualStudio.TestTools.UnitTesting;
    using VividCryptography;

    [TestClass]
    public class VividHashingTesting
    {
        [TestMethod]
        public void GetSaltTest()
        {
            var hashing = new VividHashing();
            var salt = hashing.GetSalt();

            Assert.IsTrue(salt != null);
            Assert.IsTrue(salt.Length == 32);

            var repeatSalt = hashing.GetSalt();
            Assert.AreNotEqual(salt, repeatSalt);
        }

        [TestMethod]
        public void GetCipherTextTest()
        {
            string plainText = "Hello world!";
            var hashing = new VividHashing();
            // not empty
            var salt = hashing.GetSalt();
            var cipher = hashing.GetCipherText(plainText, salt);
            Assert.IsTrue(!string.IsNullOrEmpty(cipher));
            Assert.IsTrue(cipher.Length == 512);

            // the same result always
            var repeatCipher = hashing.GetCipherText(plainText, salt);
            Assert.AreEqual(cipher, repeatCipher);

            // cannot be duplicated
            var anotherCipher = hashing.GetCipherText(plainText + "s", salt);
            Assert.AreNotEqual(cipher, anotherCipher);

            // not the same with new salt
            var newSalt = hashing.GetSalt();
            var newCipher = hashing.GetCipherText(plainText, newSalt);
            Assert.AreNotEqual(cipher, newCipher);
        }

        [TestMethod]
        public void CompateHashTest()
        {
            string plainText = "Hello world!";
            var hashing = new VividHashing();
            // match
            var salt = hashing.GetSalt();
            var oldHash = hashing.GetCipherText(plainText, salt);
            Assert.IsTrue(hashing.CompareHash(plainText, oldHash, salt));

            // different salt
            var anotherSalt = hashing.GetSalt();
            Assert.IsFalse(hashing.CompareHash(plainText, oldHash, anotherSalt));

            // different hash
            var anotherHash = hashing.GetCipherText(plainText, anotherSalt);
            Assert.IsFalse(hashing.CompareHash(plainText, anotherHash, salt));
        }
    }
}

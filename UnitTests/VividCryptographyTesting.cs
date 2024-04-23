namespace UnitTest
{
    using Microsoft.VisualStudio.TestTools.UnitTesting;
    using VividCryptography;

    [TestClass]
    public class VividCryptographyTesting
    {
        [TestMethod]
        public void EncryptDecryptTest()
        {
            string plainText = "4242424242424242";
            var crypto = new VividCryptography("ASDasd@!#!@#SDASD@E!@D!WDQDASDADR#%^GFGHGSDGTJMUIP12312541235423");
            var cipherText = crypto.Encrypt(plainText);
            var result = crypto.Decrypt(cipherText);
            Assert.AreEqual(result, plainText);

            var cipherText2 = crypto.Encrypt(plainText);
            var result2 = crypto.Decrypt(cipherText2);
            Assert.AreEqual(result2, plainText);
        }
    }
}

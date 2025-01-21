using System.Security.Cryptography;
using System.Text;

class Program
{
    static void Main()
    {
        string plaintext = "Test Cryptor";
        string password = "Password";

        Console.WriteLine("Original Text: " + plaintext);

        string encrypted = EncryptComplex(plaintext, password);
        Console.WriteLine("Encrypted: " + encrypted);

        string decrypted = DecryptComplex(encrypted, password);
        Console.WriteLine("Decrypted: " + decrypted);
    }

    static string EncryptComplex(string plaintext, string password)
    {
        byte[] salt = GenerateRandomBytes(16);

        byte[] key = DeriveKey(password, salt);

        byte[] xorEncrypted = XorEncrypt(plaintext, Convert.ToBase64String(salt));

        byte[] aesEncrypted = AesEncrypt(xorEncrypted, key);

        byte[] hmac = ComputeHMAC(aesEncrypted, key);

        byte[] finalData = new byte[salt.Length + aesEncrypted.Length + hmac.Length];
        Array.Copy(salt, 0, finalData, 0, salt.Length);
        Array.Copy(aesEncrypted, 0, finalData, salt.Length, aesEncrypted.Length);
        Array.Copy(hmac, 0, finalData, salt.Length + aesEncrypted.Length, hmac.Length);

        return Convert.ToBase64String(finalData);
    }

    static string DecryptComplex(string encrypted, string password)
    {
        byte[] fullData = Convert.FromBase64String(encrypted);

        byte[] salt = new byte[16];
        byte[] hmac = new byte[32];
        byte[] aesEncrypted = new byte[fullData.Length - salt.Length - hmac.Length];

        Array.Copy(fullData, 0, salt, 0, salt.Length);
        Array.Copy(fullData, salt.Length, aesEncrypted, 0, aesEncrypted.Length);
        Array.Copy(fullData, salt.Length + aesEncrypted.Length, hmac, 0, hmac.Length);

        byte[] key = DeriveKey(password, salt);

        if (!VerifyHMAC(aesEncrypted, hmac, key))
            throw new CryptographicException("HMAC verification failed!");

        byte[] xorEncrypted = AesDecrypt(aesEncrypted, key);

        return XorDecrypt(xorEncrypted, Convert.ToBase64String(salt));
    }

    static byte[] DeriveKey(string password, byte[] salt)
    {
        using (var pbkdf2 = new Rfc2898DeriveBytes(password, salt, 100000))
        {
            return pbkdf2.GetBytes(32);
        }
    }

    static byte[] GenerateRandomBytes(int length)
    {
        byte[] randomBytes = new byte[length];
        using (var rng = new RNGCryptoServiceProvider())
        {
            rng.GetBytes(randomBytes);
        }
        return randomBytes;
    }

    static byte[] XorEncrypt(string plaintext, string key)
    {
        byte[] data = Encoding.UTF8.GetBytes(plaintext);
        byte[] keyBytes = Encoding.UTF8.GetBytes(key);
        byte[] result = new byte[data.Length];

        for (int i = 0; i < data.Length; i++)
            result[i] = (byte)(data[i] ^ keyBytes[i % keyBytes.Length]);

        return result;
    }

    static string XorDecrypt(byte[] data, string key)
    {
        return Encoding.UTF8.GetString(XorEncrypt(Encoding.UTF8.GetString(data), key));
    }

    static byte[] AesEncrypt(byte[] data, byte[] key)
    {
        using (Aes aes = Aes.Create())
        {
            aes.Key = key;
            aes.GenerateIV();
            byte[] iv = aes.IV;

            using (MemoryStream ms = new MemoryStream())
            {
                ms.Write(iv, 0, iv.Length);
                using (CryptoStream cs = new CryptoStream(ms, aes.CreateEncryptor(), CryptoStreamMode.Write))
                {
                    cs.Write(data, 0, data.Length);
                }
                return ms.ToArray();
            }
        }
    }

    static byte[] AesDecrypt(byte[] data, byte[] key)
    {
        using (Aes aes = Aes.Create())
        {
            aes.Key = key;

            byte[] iv = new byte[16];
            Array.Copy(data, 0, iv, 0, iv.Length);
            aes.IV = iv;

            using (MemoryStream ms = new MemoryStream())
            {
                using (CryptoStream cs = new CryptoStream(ms, aes.CreateDecryptor(), CryptoStreamMode.Write))
                {
                    cs.Write(data, iv.Length, data.Length - iv.Length);
                }
                return ms.ToArray();
            }
        }
    }

    static byte[] ComputeHMAC(byte[] data, byte[] key)
    {
        using (var hmac = new HMACSHA256(key))
        {
            return hmac.ComputeHash(data);
        }
    }

    static bool VerifyHMAC(byte[] data, byte[] hmac, byte[] key)
    {
        byte[] computedHmac = ComputeHMAC(data, key);
        return computedHmac.SequenceEqual(hmac);
    }
}

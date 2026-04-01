using System.Security.Cryptography;
using System.Text;

namespace HashKrypto.ConsoleApp;

internal static class RsaStringCipher
{
     
    public static int GetMaxPlaintextBytes(int rsaKeySizeBits)
    {
        int k = rsaKeySizeBits / 8;
        const int h = 32; 
        return k - 2 * h - 2;
    }

    public static string Encrypt(string plaintext, RSA rsaPublic)
    {
        byte[] plain = Encoding.UTF8.GetBytes(plaintext);
        int max = GetMaxPlaintextBytes(rsaPublic.KeySize);
        if (plain.Length > max)
            throw new InvalidOperationException(
                $"RSA ({rsaPublic.KeySize} бит): не больше {max} байт в UTF-8 (сейчас {plain.Length}). Для длинного текста используйте AES.");

        byte[] cipher = rsaPublic.Encrypt(plain, RSAEncryptionPadding.OaepSHA256);
        return Convert.ToBase64String(cipher);
    }

    public static string Decrypt(string base64Ciphertext, RSA rsaPrivate)
    {
        byte[] cipher = Convert.FromBase64String(base64Ciphertext);
        byte[] plain = rsaPrivate.Decrypt(cipher, RSAEncryptionPadding.OaepSHA256);
        return Encoding.UTF8.GetString(plain);
    }
}

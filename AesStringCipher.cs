using System.Security.Cryptography;
using System.Text;

namespace HashKrypto.ConsoleApp;

internal static class AesStringCipher
{
    public static string Encrypt(string plaintext, ReadOnlySpan<byte> key)
    {
        if (key.Length != 32)
            throw new ArgumentException("Ключ AES-256 должен быть 32 байта.", nameof(key));

        using var aes = Aes.Create();
        aes.KeySize = 256;
        aes.Mode = CipherMode.CBC;
        aes.Padding = PaddingMode.PKCS7;
        aes.Key = key.ToArray();
        aes.GenerateIV();

        byte[] plain = Encoding.UTF8.GetBytes(plaintext);
        byte[] cipher = aes.EncryptCbc(plain, aes.IV);

        byte[] packet = new byte[aes.IV.Length + cipher.Length];
        aes.IV.CopyTo(packet);
        cipher.CopyTo(packet.AsSpan(aes.IV.Length));

        return Convert.ToBase64String(packet);
    }

    public static string Decrypt(string base64Ciphertext, ReadOnlySpan<byte> key)
    {
        if (key.Length != 32)
            throw new ArgumentException("Ключ AES-256 должен быть 32 байта.", nameof(key));

        byte[] packet = Convert.FromBase64String(base64Ciphertext);
        if (packet.Length <= 16)
            throw new CryptographicException("Некорректные данные AES.");

        ReadOnlySpan<byte> iv = packet.AsSpan(0, 16);
        ReadOnlySpan<byte> cipher = packet.AsSpan(16);

        using var aes = Aes.Create();
        aes.KeySize = 256;
        aes.Mode = CipherMode.CBC;
        aes.Padding = PaddingMode.PKCS7;
        aes.Key = key.ToArray();

        byte[] plain = aes.DecryptCbc(cipher.ToArray(), iv.ToArray());
        return Encoding.UTF8.GetString(plain);
    }
}

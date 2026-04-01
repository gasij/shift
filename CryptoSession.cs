using System.Security.Cryptography;

namespace HashKrypto.ConsoleApp;

internal static class CryptoSession
{
    private static byte[]? _aesKey;
    private static byte[]? _customKey;
    private static RSA? _rsa;

    public static byte[] GetOrCreateAesKey()
    {
        if (_aesKey is null)
        {
            _aesKey = new byte[32];
            RandomNumberGenerator.Fill(_aesKey);
        }

        return _aesKey;
    }

    public static byte[] GetOrCreateCustomKey()
    {
        if (_customKey is null)
        {
            _customKey = new byte[32];
            RandomNumberGenerator.Fill(_customKey);
        }

        return _customKey;
    }

    public static RSA GetOrCreateRsa()
    {
        if (_rsa is null)
            _rsa = RSA.Create(2048);

        return _rsa;
    }
}

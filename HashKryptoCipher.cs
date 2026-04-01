using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;

namespace HashKrypto.ConsoleApp;

// Учебный шифр HashKrypto — не для реальных секретов.
internal static class HashKryptoCipher
{
    private static ReadOnlySpan<byte> Magic => "HK"u8;

    public static string Encrypt(string plaintext, ReadOnlySpan<byte> key)
    {
        if (key.Length != 32)
            throw new ArgumentException("Ключ должен быть 32 байта.", nameof(key));

        byte[] plain = Encoding.UTF8.GetBytes(plaintext);
        Span<byte> nonce = stackalloc byte[8];
        RandomNumberGenerator.Fill(nonce);

        byte[] mixed = new byte[plain.Length];
        ApplyPreMix(plain, mixed, key, nonce);

        byte[] rolled = new byte[plain.Length];
        for (int i = 0; i < plain.Length; i++)
            rolled[i] = Rol(mixed[i], RotationSteps(i, nonce));

        byte[] keystream = new byte[plain.Length];
        FillKeystream(key, nonce, keystream);

        byte[] cipher = new byte[plain.Length];
        for (int i = 0; i < plain.Length; i++)
            cipher[i] = (byte)(NibbleSwap(rolled[i]) ^ keystream[i]);

        byte[] packet = new byte[8 + cipher.Length];
        nonce.CopyTo(packet);
        cipher.CopyTo(packet.AsSpan(8));

        return Convert.ToBase64String(packet);
    }

    public static string Decrypt(string base64Payload, ReadOnlySpan<byte> key)
    {
        if (key.Length != 32)
            throw new ArgumentException("Ключ должен быть 32 байта.", nameof(key));

        byte[] packet = Convert.FromBase64String(base64Payload);
        if (packet.Length <= 8)
            throw new CryptographicException("Слишком короткий пакет HashKrypto.");

        ReadOnlySpan<byte> nonce = packet.AsSpan(0, 8);
        ReadOnlySpan<byte> cipher = packet.AsSpan(8);

        byte[] keystream = new byte[cipher.Length];
        FillKeystream(key, nonce, keystream);

        byte[] rolled = new byte[cipher.Length];
        for (int i = 0; i < cipher.Length; i++)
            rolled[i] = NibbleSwap((byte)(cipher[i] ^ keystream[i]));

        byte[] mixed = new byte[cipher.Length];
        for (int i = 0; i < cipher.Length; i++)
            mixed[i] = Ror(rolled[i], RotationSteps(i, nonce));

        byte[] plain = new byte[cipher.Length];
        ApplyPreMixInverse(mixed, plain, key, nonce);

        return Encoding.UTF8.GetString(plain);
    }

    private static void ApplyPreMix(ReadOnlySpan<byte> input, Span<byte> output, ReadOnlySpan<byte> key, ReadOnlySpan<byte> nonce)
    {
        for (int i = 0; i < input.Length; i++)
        {
            byte tweak = (byte)(i + nonce[i % 8]);
            output[i] = (byte)(input[i] ^ key[i % 32] ^ tweak);
        }
    }

    private static void ApplyPreMixInverse(ReadOnlySpan<byte> input, Span<byte> output, ReadOnlySpan<byte> key, ReadOnlySpan<byte> nonce)
    {
        ApplyPreMix(input, output, key, nonce);
    }

    private static byte NibbleSwap(byte b) => (byte)((b >> 4) | (b << 4));

    private static int RotationSteps(int index, ReadOnlySpan<byte> nonce) =>
        (nonce[index % 8] + index) & 7;

    private static byte Rol(byte b, int r)
    {
        r &= 7;
        return (byte)((b << r) | (b >> (8 - r)));
    }

    private static byte Ror(byte b, int r)
    {
        r &= 7;
        return (byte)((b >> r) | (b << (8 - r)));
    }

    private static void FillKeystream(ReadOnlySpan<byte> key, ReadOnlySpan<byte> nonce, Span<byte> output)
    {
        Span<byte> preimage = stackalloc byte[Magic.Length + 32 + 8 + 8];
        Magic.CopyTo(preimage);
        key.CopyTo(preimage.Slice(Magic.Length));
        nonce.CopyTo(preimage.Slice(Magic.Length + 32));
        int fixedLen = Magic.Length + 32 + 8;

        int written = 0;
        ulong counter = 0;
        Span<byte> hash = stackalloc byte[SHA256.HashSizeInBytes];

        while (written < output.Length)
        {
            BinaryPrimitives.WriteUInt64LittleEndian(preimage.Slice(fixedLen), counter);
            SHA256.HashData(preimage, hash);

            int take = Math.Min(hash.Length, output.Length - written);
            hash.Slice(0, take).CopyTo(output.Slice(written));
            written += take;
            counter++;
        }
    }
}

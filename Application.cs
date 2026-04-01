using System.Security.Cryptography;

namespace HashKrypto.ConsoleApp;

internal static class Application
{
    public static Task<int> RunAsync(string[] args)
    {
        Console.OutputEncoding = System.Text.Encoding.UTF8;
        Console.WriteLine("Шифрование строк (ключи хранятся в памяти до выхода из программы).");

        while (true)
        {
            Console.WriteLine();
            Console.WriteLine("Тип шифрования:");
            Console.WriteLine("  1 — AES-256 (симметричное, длинные строки)");
            Console.WriteLine("  2 — RSA-2048 (асимметричное, только короткая строка)");
            Console.WriteLine("  3 — HashKrypto (своя схема, см. README)");
            Console.WriteLine("  0 — выход");
            Console.Write("> ");

            string? modeLine = Console.ReadLine();
            if (string.IsNullOrWhiteSpace(modeLine) || modeLine.Trim() == "0")
                break;

            int mode = int.TryParse(modeLine.Trim(), out int m) ? m : -1;
            if (mode is not (1 or 2 or 3))
            {
                Console.WriteLine("Введите 1, 2, 3 или 0.");
                continue;
            }

            Console.WriteLine("Действие:");
            Console.WriteLine("  1 — зашифровать");
            Console.WriteLine("  2 — расшифровать");
            Console.Write("> ");

            string? actionLine = Console.ReadLine();
            if (!int.TryParse(actionLine?.Trim(), out int action) || action is not (1 or 2))
            {
                Console.WriteLine("Введите 1 или 2.");
                continue;
            }

            try
            {
                if (mode == 1)
                    RunAes(action == 1);
                else if (mode == 2)
                    RunRsa(action == 1);
                else
                    RunCustom(action == 1);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Ошибка: {ex.Message}");
            }
        }

        return Task.FromResult(0);
    }

    private static void RunAes(bool encrypt)
    {
        byte[] key = CryptoSession.GetOrCreateAesKey();

        if (encrypt)
        {
            Console.Write("Строка для шифрования: ");
            string? text = Console.ReadLine() ?? "";
            string b64 = AesStringCipher.Encrypt(text, key);
            Console.WriteLine("Base64:");
            Console.WriteLine(b64);
        }
        else
        {
            Console.Write("Base64 для расшифровки: ");
            string? b64 = Console.ReadLine()?.Trim() ?? "";
            string plain = AesStringCipher.Decrypt(b64, key);
            Console.WriteLine("Расшифровано:");
            Console.WriteLine(plain);
        }
    }

    private static void RunRsa(bool encrypt)
    {
        RSA rsa = CryptoSession.GetOrCreateRsa();
        int max = RsaStringCipher.GetMaxPlaintextBytes(rsa.KeySize);

        if (encrypt)
        {
            Console.WriteLine($"Лимит открытого текста: до {max} байт в UTF-8.");
            Console.Write("Строка для шифрования: ");
            string? text = Console.ReadLine() ?? "";
            string b64 = RsaStringCipher.Encrypt(text, rsa);
            Console.WriteLine("Base64:");
            Console.WriteLine(b64);
        }
        else
        {
            Console.Write("Base64 для расшифровки: ");
            string? b64 = Console.ReadLine()?.Trim() ?? "";
            string plain = RsaStringCipher.Decrypt(b64, rsa);
            Console.WriteLine("Расшифровано:");
            Console.WriteLine(plain);
        }
    }

    private static void RunCustom(bool encrypt)
    {
        byte[] key = CryptoSession.GetOrCreateCustomKey();

        if (encrypt)
        {
            Console.Write("Строка для шифрования: ");
            string? text = Console.ReadLine() ?? "";
            string b64 = HashKryptoCipher.Encrypt(text, key);
            Console.WriteLine("Base64:");
            Console.WriteLine(b64);
        }
        else
        {
            Console.Write("Base64 для расшифровки: ");
            string? b64 = Console.ReadLine()?.Trim() ?? "";
            string plain = HashKryptoCipher.Decrypt(b64, key);
            Console.WriteLine("Расшифровано:");
            Console.WriteLine(plain);
        }
    }
}

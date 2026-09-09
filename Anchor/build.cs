using System;

class Program
{
    static void Main()
    {
        // 1. Print the ASCII Art Banner
        Console.WriteLine(@" .---.
/     \
\     /
 `---'

   | |
___|___
/     \

|  _  |
| (_) |
|     |
|     |
|     |
|     |
|     |
|     |
|  __ |
| |  __ \
\ \|  |/ /
 \ \  / /
  \ \/ /
   `--'
   `--'
 /     \
`.     .'
  `-._.-'
  /     \
 /_______\" + Environment.NewLine);

        // 2. Print your application details
        Console.WriteLine("========================================");
        Console.WriteLine("Welcome to Anchor Brute-Forcer v1.2, We hope you will enjoy using it!");
        Console.WriteLine("========================================");
        Console.WriteLine();
        Console.WriteLine("Advanced Features:");
        Console.WriteLine("- HTTP/HTTPS form authentication cracking");
        Console.WriteLine("- Multiple protocol support (SSH, SMB, RDP, FTP, MySQL, PostgreSQL, MSSQL)");
        Console.WriteLine("- Cookie support");
        Console.WriteLine("- Proxy support");
        Console.WriteLine("- Custom headers");
        Console.WriteLine("- Success/Failure pattern matching");
        Console.WriteLine("- Rate limiting detection");
        Console.WriteLine("- Resume support");
        Console.WriteLine();
        Console.WriteLine("Usage Examples:");
        Console.WriteLine("  anchor.exe -target example.com -username admin -wordlist passwords.txt -protocol http -success \"Welcome\" -fail \"Invalid\"");
        Console.WriteLine("  anchor.exe -target example.com -username admin -wordlist passwords.txt -protocol https -form-action /login -method POST");
        Console.WriteLine("  anchor.exe -target 192.168.1.100 -username admin -wordlist passwords.txt -protocol ssh -concurrency 200");
        Console.WriteLine("  anchor.exe -target 192.168.1.100 -username root -wordlist passwords.txt -protocol mysql -port 3306");
        Console.WriteLine();

        // 3. Keep the console window open (equivalent to pause)
        Console.WriteLine("Press any key to continue . . .");
        Console.ReadKey();
    }
}

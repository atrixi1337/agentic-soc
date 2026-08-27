// soc-fetch-sample.exe - Wazuh AR launcher shim (v4).
// Launched by execd as SYSTEM. If no argv/stdin, reads the rendezvous file
// C:\Users\victim\soc-ar\pending_fetch.json (written by the bridge) and
// passes -Path/-AlertId to the PowerShell fetcher.
using System;
using System.Diagnostics;
using System.IO;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;

class FetchLaunch
{
    const string PENDING = "C:\\Users\\victim\\soc-ar\\pending_fetch.json";

    static void Dbg(string m)
    {
        try { File.AppendAllText("C:\\Quarantine\\shim_debug.txt",
            DateTime.Now.ToString("s") + " " + m + "\r\n"); } catch {}
    }

    static string Esc(string s)
    {
        return s.Replace("\\", "\\\\").Replace("\"", "\\\"");
    }

    static int Main(string[] args)
    {
        Dbg("=== shim start, cmdline: " + Environment.CommandLine);
        string path = "";
        string alertId = "";

        // 1) argv on the command line
        if (args.Length >= 1) path = args[0];
        if (args.Length >= 2) alertId = args[1];
        if (path.Length == 0)
        {
            // 2) rendezvous file written by the bridge
            try
            {
                if (File.Exists(PENDING))
                {
                    string raw = File.ReadAllText(PENDING);
                    Dbg("pending=" + raw.Substring(0, Math.Min(160, raw.Length)));
                    var m2 = Regex.Matches(raw,
                        "\"(path|alert_id)\"\\s*:\\s*\"([^\"]*)\"", RegexOptions.IgnoreCase);
                    foreach (Match mm in m2)
                    {
                        if (mm.Groups[1].Value.ToLower() == "path" && path.Length == 0)
                            path = mm.Groups[2].Value;
                        else if (mm.Groups[1].Value.ToLower() == "alert_id" && alertId.Length == 0)
                            alertId = mm.Groups[2].Value;
                    }
                    // if path was empty, try a bare windows path
                    if (path.Length == 0)
                    {
                        var p = Regex.Match(raw, "[A-Za-z]:\\\\[^\"\\s]+");
                        if (p.Success) path = p.Value.Trim();
                    }
                    Dbg("from-pending path=" + path + " alert=" + alertId);
                }
            }
            catch (Exception e) { Dbg("pending-read FAIL " + e.Message); }
        }

        try
        {
            Directory.CreateDirectory("C:\\Quarantine");
            string ps1 = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "soc-fetch-sample.ps1");
            Dbg("ps1 path=" + ps1 + " exists=" + File.Exists(ps1));

            var psi = new ProcessStartInfo();
            psi.FileName = Path.Combine(Environment.SystemDirectory, @"WindowsPowerShell\v1.0\powershell.exe");
            var argb = new StringBuilder();
            argb.Append("-NoProfile -ExecutionPolicy Bypass -File \"").Append(ps1).Append("\"");
            if (path.Length > 0) argb.Append(" -Path \"").Append(path).Append("\"");
            if (alertId.Length > 0) argb.Append(" -AlertId \"").Append(alertId).Append("\"");
            psi.Arguments = argb.ToString();
            psi.CreateNoWindow = true;
            psi.UseShellExecute = false;
            Process.Start(psi);
            Dbg("powershell launched: " + psi.Arguments);
        }
        catch (Exception e) { Dbg("LAUNCH FAIL: " + e); }

        return 0;
    }
}
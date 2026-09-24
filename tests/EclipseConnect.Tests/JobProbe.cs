using System.Diagnostics;
using EclipseConnect.Core;

internal static class JobProbe
{
    public static int Run()
    {
        if (!OperatingSystem.IsWindows()) return 1;
        Process? child = null;
        try
        {
            var start = new ProcessStartInfo(Environment.ProcessPath!) { UseShellExecute = false, CreateNoWindow = true };
            if (string.Equals(Path.GetFileNameWithoutExtension(Environment.ProcessPath), "dotnet", StringComparison.OrdinalIgnoreCase))
                start.ArgumentList.Add(typeof(JobProbe).Assembly.Location);
            start.ArgumentList.Add("--job-child");
            child = Process.Start(start) ?? throw new Exception("No test child");
            using (var job = new ProcessJob())
            {
                job.Assign(child);
                if (child.WaitForExit(300)) throw new Exception("Test child exited before job close");
            }
            if (!child.WaitForExit(5000)) throw new Exception("Job did not terminate test child");
            Console.WriteLine("PASS Windows Job Object: own harmless test child stopped after handle close; no driver or network component launched.");
            return 0;
        }
        catch (Exception e) { Console.WriteLine("FAIL Job Object: " + e.GetType().Name); return 1; }
        finally
        {
            if (child != null) { if (!child.HasExited) { child.Kill(true); child.WaitForExit(5000); } child.Dispose(); }
        }
    }
}

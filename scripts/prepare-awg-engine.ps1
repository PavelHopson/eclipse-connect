param()
$ErrorActionPreference = 'Stop'
# Preparation only: read a hash-pinned MSI as a database/cabinet; never execute installer actions.
$connectRoot = Split-Path -Parent $PSScriptRoot
$connectMsi = Join-Path $connectRoot '.cache/amneziawg-amd64-3.1.0.msi'
$connectDigest = 'a1b48ea8699cd347832a3691d832004574ef8ad65bcf887611ac8acb99b7de8b'
New-Item -ItemType Directory -Path (Split-Path -Parent $connectMsi) -Force | Out-Null
if (-not (Test-Path -LiteralPath $connectMsi)) {
    Invoke-WebRequest -Uri 'https://github.com/amnezia-vpn/amneziawg-windows-client/releases/download/3.1.0/amneziawg-amd64-3.1.0.msi' -OutFile $connectMsi -TimeoutSec 60
}
if ((Get-Item -LiteralPath $connectMsi).Length -ne 3641344 -or (Get-FileHash -LiteralPath $connectMsi).Hash -ne $connectDigest) { throw 'MSI release SHA-256/size mismatch' }
Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
public static class ConnectMsiReadOnly {
    [DllImport("msi.dll", CharSet=CharSet.Unicode)] static extern uint MsiOpenDatabase(string path, IntPtr mode, out uint db);
    [DllImport("msi.dll", CharSet=CharSet.Unicode)] static extern uint MsiDatabaseOpenView(uint db, string sql, out uint view);
    [DllImport("msi.dll")] static extern uint MsiViewExecute(uint view, uint record);
    [DllImport("msi.dll")] static extern uint MsiViewFetch(uint view, out uint record);
    [DllImport("msi.dll", CharSet=CharSet.Unicode)] static extern uint MsiRecordGetString(uint record, uint field, StringBuilder value, ref uint length);
    [DllImport("msi.dll")] static extern uint MsiRecordReadStream(uint record, uint field, byte[] buffer, ref uint length);
    [DllImport("msi.dll")] static extern uint MsiCloseHandle(uint handle);
    static void Check(uint code) { if(code != 0) throw new IOException("MSI read failed: " + code); }
    static uint View(uint db, string sql) { uint v; Check(MsiDatabaseOpenView(db, sql, out v)); Check(MsiViewExecute(v, 0)); return v; }
    public static string[][] Rows(string path, string sql, uint columns) {
        uint db; Check(MsiOpenDatabase(path, IntPtr.Zero, out db));
        try { uint v = View(db, sql); try {
            var rows = new List<string[]>(); uint record; uint status;
            while ((status=MsiViewFetch(v, out record)) == 0) { try {
                if (rows.Count >= 100) throw new IOException("Too many MSI rows");
                var values = new string[columns];
                for(uint c=1;c<=columns;c++) { uint size=1024; var s=new StringBuilder(1024); Check(MsiRecordGetString(record,c,s,ref size)); values[c-1]=s.ToString(); }
                rows.Add(values);
            } finally { MsiCloseHandle(record); } }
            if(status != 259) Check(status); return rows.ToArray();
        } finally { MsiCloseHandle(v); } } finally { MsiCloseHandle(db); }
    }
    public static void Cabinet(string path, string name, string output) {
        if(!System.Text.RegularExpressions.Regex.IsMatch(name,@"\A[A-Za-z0-9_.-]+\z")) throw new IOException("Invalid cabinet name");
        uint db; Check(MsiOpenDatabase(path,IntPtr.Zero,out db));
        try { uint v=View(db,"SELECT `Data` FROM `_Streams` WHERE `Name`='"+name+"'"); try {
            uint record; Check(MsiViewFetch(v,out record)); try {
                using(var file=new FileStream(output,FileMode.CreateNew,FileAccess.Write,FileShare.None)) {
                    var buffer=new byte[65536]; long total=0;
                    while(true) { uint count=(uint)buffer.Length; Check(MsiRecordReadStream(record,1,buffer,ref count)); if(count==0) break;
                        total+=count; if(total>8*1024*1024) throw new IOException("Cabinet too large"); file.Write(buffer,0,(int)count); }
                }
            } finally { MsiCloseHandle(record); }
        } finally { MsiCloseHandle(v); } } finally { MsiCloseHandle(db); }
    }
}
'@
$connectFiles = [ConnectMsiReadOnly]::Rows($connectMsi, 'SELECT `File`,`FileName`,`FileSize` FROM `File`', 3)
$connectMedia = [ConnectMsiReadOnly]::Rows($connectMsi, 'SELECT `Cabinet` FROM `Media`', 1)
$connectStage = Join-Path $connectRoot ('.cache/awg-unpack-' + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $connectStage | Out-Null
$connectOutput = Join-Path $connectRoot 'artifacts/awg-engine/3.1.0'
New-Item -ItemType Directory -Path $connectOutput -Force | Out-Null
if ($connectMedia.Count -ne 1 -or -not $connectMedia[0][0].StartsWith('#')) { throw 'Unexpected cabinet layout' }
$connectCabinet = Join-Path $connectStage 'engine.cab'
[ConnectMsiReadOnly]::Cabinet($connectMsi, $connectMedia[0][0].Substring(1), $connectCabinet)
foreach ($connectRow in $connectFiles) {
    $connectName = ($connectRow[1] -split '\|')[-1]
    if ($connectName -notin @('amneziawg.exe','awg.exe','wintun.dll')) { continue }
    if ($connectRow[0] -notmatch '\A[A-Za-z0-9_.-]+\z') { throw 'Unexpected cabinet member' }
    & "$env:SystemRoot\System32\expand.exe" ('-F:' + $connectRow[0]) $connectCabinet $connectStage | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Cabinet extraction failed' }
    $connectExtracted = Join-Path $connectStage $connectRow[0]
    if ((Get-Item -LiteralPath $connectExtracted).Length -ne [long]$connectRow[2]) { throw 'Extracted size mismatch' }
    Copy-Item -LiteralPath $connectExtracted -Destination (Join-Path $connectOutput $connectName)
    Get-FileHash -LiteralPath (Join-Path $connectOutput $connectName) | Select-Object Hash,Path
}
Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/amnezia-vpn/amneziawg-windows-client/3.1.0/COPYING' -OutFile (Join-Path $connectOutput 'COPYING') -TimeoutSec 20
Write-Output 'Prepared only. No MSI actions, service, driver or tunnel started.'

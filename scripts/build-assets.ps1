$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName PresentationCore,WindowsBase
$connectAssetDir = Join-Path (Split-Path -Parent $PSScriptRoot) 'src\EclipseConnect.App\Assets'
New-Item -ItemType Directory -Path $connectAssetDir -Force | Out-Null
$connectFrames = @()
foreach ($connectSize in @(16,24,32,48,64,128,256)) {
    $connectVisual = [System.Windows.Media.DrawingVisual]::new()
    $connectContext = $connectVisual.RenderOpen()
    $connectBrush = [System.Windows.Media.SolidColorBrush]::new([System.Windows.Media.ColorConverter]::ConvertFromString('#255DA1'))
    $connectContext.DrawRoundedRectangle($connectBrush,$null,[System.Windows.Rect]::new(0,0,$connectSize,$connectSize),($connectSize*0.19),($connectSize*0.19))
    # Official Windows Segoe MDL2 Assets "Connect" glyph E703; not a hand-drawn replacement icon.
    $connectTypeface = [System.Windows.Media.Typeface]::new('Segoe MDL2 Assets')
    $connectText = [System.Windows.Media.FormattedText]::new([string][char]0xE703,[Globalization.CultureInfo]::InvariantCulture,[System.Windows.FlowDirection]::LeftToRight,$connectTypeface,($connectSize*0.61),[System.Windows.Media.Brushes]::White,1.0)
    $connectContext.DrawText($connectText,[System.Windows.Point]::new(($connectSize-$connectText.Width)/2,($connectSize-$connectText.Height)/2))
    $connectContext.Close()
    $connectBitmap = [System.Windows.Media.Imaging.RenderTargetBitmap]::new($connectSize,$connectSize,96,96,[System.Windows.Media.PixelFormats]::Pbgra32)
    $connectBitmap.Render($connectVisual)
    $connectEncoder = [System.Windows.Media.Imaging.PngBitmapEncoder]::new()
    $connectEncoder.Frames.Add([System.Windows.Media.Imaging.BitmapFrame]::Create($connectBitmap))
    $connectMemory = [IO.MemoryStream]::new(); $connectEncoder.Save($connectMemory)
    $connectFrames += [pscustomobject]@{ Size=$connectSize; Bytes=$connectMemory.ToArray() }; $connectMemory.Dispose()
}
$connectIcon = [IO.BinaryWriter]::new([IO.File]::Create((Join-Path $connectAssetDir 'Connect.ico')))
try {
    $connectIcon.Write([uint16]0); $connectIcon.Write([uint16]1); $connectIcon.Write([uint16]$connectFrames.Count)
    $connectOffset = 6 + 16*$connectFrames.Count
    foreach ($connectFrame in $connectFrames) {
        $connectSide = if ($connectFrame.Size -eq 256) { 0 } else { $connectFrame.Size }
        $connectIcon.Write([byte]$connectSide); $connectIcon.Write([byte]$connectSide); $connectIcon.Write([byte]0); $connectIcon.Write([byte]0)
        $connectIcon.Write([uint16]1); $connectIcon.Write([uint16]32); $connectIcon.Write([uint32]$connectFrame.Bytes.Length); $connectIcon.Write([uint32]$connectOffset)
        $connectOffset += $connectFrame.Bytes.Length
    }
    foreach ($connectFrame in $connectFrames) { $connectIcon.Write([byte[]]$connectFrame.Bytes) }
} finally { $connectIcon.Dispose() }

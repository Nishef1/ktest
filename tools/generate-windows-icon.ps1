param(
    [string]$IconPath = (Join-Path $PSScriptRoot '..\assets\ktest.ico'),
    [string]$ResourcePath = (Join-Path $PSScriptRoot '..\cmd\ktest\ktest-icon_windows_amd64.syso')
)

$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Drawing

function New-IconBitmap([int]$size) {
    $bitmap = [Drawing.Bitmap]::new($size, $size, [Drawing.Imaging.PixelFormat]::Format32bppArgb)
    $graphics = [Drawing.Graphics]::FromImage($bitmap)
    try {
        $graphics.SmoothingMode = [Drawing.Drawing2D.SmoothingMode]::AntiAlias
        $graphics.CompositingQuality = [Drawing.Drawing2D.CompositingQuality]::HighQuality
        $graphics.InterpolationMode = [Drawing.Drawing2D.InterpolationMode]::HighQualityBicubic
        $graphics.PixelOffsetMode = [Drawing.Drawing2D.PixelOffsetMode]::HighQuality

        $background = [Drawing.Drawing2D.LinearGradientBrush]::new(
            [Drawing.Point]::new(0, 0), [Drawing.Point]::new($size, $size),
            [Drawing.Color]::FromArgb(255, 14, 34, 48),
            [Drawing.Color]::FromArgb(255, 5, 8, 12))
        try { $graphics.FillRectangle($background, 0, 0, $size, $size) } finally { $background.Dispose() }

        $glowPath = [Drawing.Drawing2D.GraphicsPath]::new()
        try {
            $glowPath.AddEllipse($size * 0.185, $size * 0.185, $size * 0.63, $size * 0.63)
            $glow = [Drawing.Drawing2D.PathGradientBrush]::new($glowPath)
            try {
                $glow.CenterColor = [Drawing.Color]::FromArgb(80, 94, 242, 196)
                $glow.SurroundColors = @([Drawing.Color]::FromArgb(0, 94, 242, 196))
                $graphics.FillPath($glow, $glowPath)
            } finally { $glow.Dispose() }
        } finally { $glowPath.Dispose() }

        $accent = [Drawing.Drawing2D.LinearGradientBrush]::new(
            [Drawing.Point]::new($size * 0.20, $size * 0.18), [Drawing.Point]::new($size * 0.80, $size * 0.82),
            [Drawing.Color]::FromArgb(255, 94, 242, 196),
            [Drawing.Color]::FromArgb(255, 63, 194, 245))
        try {
            $stroke = [Drawing.Pen]::new($accent, [Math]::Max(2.0, $size * 0.075))
            try {
                $stroke.StartCap = [Drawing.Drawing2D.LineCap]::Round
                $stroke.EndCap = [Drawing.Drawing2D.LineCap]::Round
                $box = $size * 0.22
                $diameter = $size * 0.56
                $graphics.DrawArc($stroke, $box, $box, $diameter, $diameter, 45, 270)
            } finally { $stroke.Dispose() }

            $stemWidth = [Math]::Max(2.0, $size * 0.075)
            $stem = [Drawing.RectangleF]::new(($size - $stemWidth) / 2, $size * 0.16, $stemWidth, $size * 0.27)
            $graphics.FillRectangle($accent, $stem)
        } finally { $accent.Dispose() }
    } finally { $graphics.Dispose() }
    return $bitmap
}

function Get-PngBytes([Drawing.Bitmap]$bitmap) {
    $stream = [IO.MemoryStream]::new()
    try {
        $bitmap.Save($stream, [Drawing.Imaging.ImageFormat]::Png)
        return ,$stream.ToArray()
    } finally { $stream.Dispose() }
}

$sizes = @(256, 128, 64, 48, 32, 16)
$images = @()
foreach ($size in $sizes) {
    $bitmap = New-IconBitmap $size
    try { $images += [pscustomobject]@{ Size = $size; Bytes = (Get-PngBytes $bitmap) } }
    finally { $bitmap.Dispose() }
}

$iconStream = [IO.MemoryStream]::new()
$writer = [IO.BinaryWriter]::new($iconStream)
try {
    $writer.Write([UInt16]0)
    $writer.Write([UInt16]1)
    $writer.Write([UInt16]$images.Count)
    $offset = 6 + (16 * $images.Count)
    foreach ($image in $images) {
        $dimension = if ($image.Size -eq 256) { 0 } else { $image.Size }
        $writer.Write([Byte]$dimension)
        $writer.Write([Byte]$dimension)
        $writer.Write([Byte]0)
        $writer.Write([Byte]0)
        $writer.Write([UInt16]1)
        $writer.Write([UInt16]32)
        $writer.Write([UInt32]$image.Bytes.Length)
        $writer.Write([UInt32]$offset)
        $offset += $image.Bytes.Length
    }
    foreach ($image in $images) { $writer.Write($image.Bytes) }
    $writer.Flush()
    $iconDirectory = Split-Path -Parent $IconPath
    New-Item -ItemType Directory -Force -Path $iconDirectory | Out-Null
    [IO.File]::WriteAllBytes($IconPath, $iconStream.ToArray())
} finally {
    $writer.Dispose()
    $iconStream.Dispose()
}

$resourceDirectory = Split-Path -Parent $ResourcePath
New-Item -ItemType Directory -Force -Path $resourceDirectory | Out-Null
$rcPath = Join-Path $resourceDirectory 'ktest-icon.rc'
$iconForRc = (Resolve-Path $IconPath).Path -replace '\\', '/'
Set-Content -LiteralPath $rcPath -Value "1 ICON DISCARDABLE `"$iconForRc`"" -Encoding ascii
& windres --target=pe-x86-64 -i $rcPath -o $ResourcePath
if ($LASTEXITCODE -ne 0) { throw "windres failed with exit code $LASTEXITCODE" }
Remove-Item -LiteralPath $rcPath -Force

Write-Output "Generated $IconPath and $ResourcePath"

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

        # Rounded tile with transparent corners (Windows does not mask icons
        # the way Android adaptive icons are masked).
        $margin = $size * 0.035
        $radius = $size * 0.22
        $tile = [Drawing.RectangleF]::new($margin, $margin, $size - 2 * $margin, $size - 2 * $margin)
        $tilePath = [Drawing.Drawing2D.GraphicsPath]::new()
        try {
            $d = $radius * 2
            $tilePath.AddArc($tile.Left, $tile.Top, $d, $d, 180, 90)
            $tilePath.AddArc($tile.Right - $d, $tile.Top, $d, $d, 270, 90)
            $tilePath.AddArc($tile.Right - $d, $tile.Bottom - $d, $d, $d, 0, 90)
            $tilePath.AddArc($tile.Left, $tile.Bottom - $d, $d, $d, 90, 90)
            $tilePath.CloseFigure()
            $background = [Drawing.Drawing2D.LinearGradientBrush]::new(
                [Drawing.PointF]::new(0, 0), [Drawing.PointF]::new($size, $size),
                [Drawing.Color]::FromArgb(255, 14, 34, 48),
                [Drawing.Color]::FromArgb(255, 5, 8, 12))
            try { $graphics.FillPath($background, $tilePath) } finally { $background.Dispose() }
        } finally { $tilePath.Dispose() }

        $center = $size / 2.0
        $small = $size -le 48
        $glowPath = [Drawing.Drawing2D.GraphicsPath]::new()
        try {
            $glowPath.AddEllipse($size * 0.18, $size * 0.18, $size * 0.64, $size * 0.64)
            $glow = [Drawing.Drawing2D.PathGradientBrush]::new($glowPath)
            try {
                $glow.CenterColor = [Drawing.Color]::FromArgb(64, 94, 242, 196)
                $glow.SurroundColors = @([Drawing.Color]::FromArgb(0, 94, 242, 196))
                if (-not $small) { $graphics.FillPath($glow, $glowPath) }
            } finally { $glow.Dispose() }
        } finally { $glowPath.Dispose() }

        # Same power glyph as the Android launcher (Material "power settings
        # new"): ring open at the top with the stem standing in the gap.
        # Unit grid: 24 units across the glyph, stroke 2, ring radius 8.
        # Small sizes drop the glow and draw a larger, bolder glyph so the ring
        # and stem stay readable at 16/32 px.
        $u = if ($small) { $size * 0.036 } else { $size * 0.026 }
        $weight = if ($small) { [Math]::Max(2.0, 2.6 * $u) } else { [Math]::Max(2.0, 2 * $u) }
        $accent = [Drawing.Drawing2D.LinearGradientBrush]::new(
            [Drawing.PointF]::new($center - 9 * $u, $center - 9 * $u), [Drawing.PointF]::new($center + 9 * $u, $center + 9 * $u),
            [Drawing.Color]::FromArgb(255, 94, 242, 196),
            [Drawing.Color]::FromArgb(255, 63, 194, 245))
        try {
            $stroke = [Drawing.Pen]::new($accent, $weight)
            try {
                $stroke.StartCap = [Drawing.Drawing2D.LineCap]::Round
                $stroke.EndCap = [Drawing.Drawing2D.LineCap]::Round
                $ringCenterY = $center + 1 * $u
                # GDI+ angles run clockwise from east; the top is 270. The gap
                # spans 230..310, so start at 310 and sweep 280.
                $graphics.DrawArc($stroke, $center - 8 * $u, $ringCenterY - 8 * $u, 16 * $u, 16 * $u, 310, 280)
                $graphics.DrawLine($stroke, $center, $ringCenterY - 9 * $u + 1 * $u, $center, $ringCenterY + 0 * $u)
            } finally { $stroke.Dispose() }
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

# Downloads the game-data files read by build.rs. The revision is pinned so
# builds are reproducible; update it and build.rs's INPUT_FILES together.
param(
    [switch]$Force
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$revision = "792978e5503ecfba73dcb3562ed44a0d35a2abe2"
$base = "https://gitlab.com/Dimbreath/animegamedata2/-/raw/$revision"
$target = Join-Path $root "3rdparty/AnimeGameData"

$files = @(
    "TextMap/TextMap_MediumEN.json"
    "ExcelBinOutput/AvatarExcelConfigData.json"
    "ExcelBinOutput/AvatarSkillDepotExcelConfigData.json"
    "ExcelBinOutput/AvatarSkillExcelConfigData.json"
    "ExcelBinOutput/ConstValueExcelConfigData.json"
    "ExcelBinOutput/EquipAffixExcelConfigData.json"
    "ExcelBinOutput/MaterialExcelConfigData.json"
    "ExcelBinOutput/ReliquaryAffixExcelConfigData.json"
    "ExcelBinOutput/ReliquaryExcelConfigData.json"
    "ExcelBinOutput/ReliquaryMainPropExcelConfigData.json"
    "ExcelBinOutput/ReliquarySetExcelConfigData.json"
    "ExcelBinOutput/WeaponExcelConfigData.json"
)

foreach ($file in $files) {
    $destination = Join-Path $target $file
    if ((Test-Path $destination) -and -not $Force) {
        continue
    }

    New-Item -ItemType Directory -Force (Split-Path $destination) | Out-Null
    Write-Host "Downloading $file"
    Invoke-WebRequest -Uri "$base/$file" -OutFile $destination -UseBasicParsing
}

Write-Host "Game data is available at $target"

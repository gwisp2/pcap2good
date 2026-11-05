#!/usr/bin/env bash
# Downloads the game-data files read by build.rs. The revision is pinned so
# builds are reproducible; update it and build.rs's INPUT_FILES together.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
revision="d54f6f0d423ded9d055bb740a3e5f3aa8f2667f1"
base="https://gitlab.com/Dimbreath/animegamedata2/-/raw/$revision"
target="$root/3rdparty/AnimeGameData"

files=(
    "TextMap/TextMap_MediumEN.json"
    "ExcelBinOutput/AvatarExcelConfigData.json"
    "ExcelBinOutput/AvatarSkillDepotExcelConfigData.json"
    "ExcelBinOutput/AvatarSkillExcelConfigData.json"
    "ExcelBinOutput/AchievementExcelConfigData.json"
    "ExcelBinOutput/BeyondHallFacilityExcelConfigData.json"
    "ExcelBinOutput/BydMaterialExcelConfigData.json"
    "ExcelBinOutput/ConstValueExcelConfigData.json"
    "ExcelBinOutput/DisplayItemExcelConfigData.json"
    "ExcelBinOutput/EquipAffixExcelConfigData.json"
    "ExcelBinOutput/HomeWorldFurnitureExcelConfigData.json"
    "ExcelBinOutput/MaterialExcelConfigData.json"
    "ExcelBinOutput/ReliquaryAffixExcelConfigData.json"
    "ExcelBinOutput/ReliquaryExcelConfigData.json"
    "ExcelBinOutput/ReliquaryMainPropExcelConfigData.json"
    "ExcelBinOutput/ReliquarySetExcelConfigData.json"
    "ExcelBinOutput/TpsWeaponExcelConfigData.json"
    "ExcelBinOutput/WeaponExcelConfigData.json"
)

for file in "${files[@]}"; do
    destination="$target/$file"
    if [[ -f "$destination" ]]; then
        continue
    fi

    mkdir -p "$(dirname "$destination")"
    echo "Downloading $file"
    curl -fsSL "$base/$file" -o "$destination"
done

echo "Game data is available at $target"

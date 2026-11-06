//! Embeds the game data (names, sets, affixes, ...) in the binary and generates
//! the protobuf types used by the bundled packet decoder.
//!
//! The data is not downloaded: the build requires a local copy of Dimbreath's
//! AnimeGameData dump at `3rdparty/AnimeGameData`. The normalization below is
//! adapted from `anime-game-data`, Copyright (c) 2025 Erik Gilling, MIT
//! licensed.

use std::collections::{HashMap, HashSet};
use std::env;
use std::fs::{self, File};
use std::io;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use flate2::Compression;
use flate2::write::GzEncoder;
use serde::Serialize;
use serde::de::DeserializeOwned;

/// Directory holding the AnimeGameData checkout, relative to the workspace root.
const GAME_DATA_SUBDIR: &str = "3rdparty/AnimeGameData";

/// Protocol definitions used by the bundled packet decoder.
const PROTO_INPUT: &str = "src/auto_artifactarium/protos.proto";

/// Files read from the data dump. Also used for Cargo rebuild tracking.
const INPUT_FILES: &[&str] = &[
    "TextMap/TextMap_MediumEN.json",
    "ExcelBinOutput/AvatarExcelConfigData.json",
    "ExcelBinOutput/AvatarSkillDepotExcelConfigData.json",
    "ExcelBinOutput/AvatarSkillExcelConfigData.json",
    "ExcelBinOutput/AchievementExcelConfigData.json",
    "ExcelBinOutput/BeyondHallFacilityExcelConfigData.json",
    "ExcelBinOutput/BydMaterialExcelConfigData.json",
    "ExcelBinOutput/ConstValueExcelConfigData.json",
    "ExcelBinOutput/DisplayItemExcelConfigData.json",
    "ExcelBinOutput/EquipAffixExcelConfigData.json",
    "ExcelBinOutput/HomeWorldFurnitureExcelConfigData.json",
    "ExcelBinOutput/MaterialExcelConfigData.json",
    "ExcelBinOutput/ReliquaryAffixExcelConfigData.json",
    "ExcelBinOutput/ReliquaryExcelConfigData.json",
    "ExcelBinOutput/ReliquaryMainPropExcelConfigData.json",
    "ExcelBinOutput/ReliquarySetExcelConfigData.json",
    "ExcelBinOutput/TpsWeaponExcelConfigData.json",
    "ExcelBinOutput/WeaponExcelConfigData.json",
];

/// Every Excel file that declares items which can appear in an inventory.
const ITEM_ID_FILES: &[&str] = &[
    "ExcelBinOutput/BeyondHallFacilityExcelConfigData.json",
    "ExcelBinOutput/BydMaterialExcelConfigData.json",
    "ExcelBinOutput/DisplayItemExcelConfigData.json",
    "ExcelBinOutput/HomeWorldFurnitureExcelConfigData.json",
    "ExcelBinOutput/MaterialExcelConfigData.json",
    "ExcelBinOutput/ReliquaryExcelConfigData.json",
    "ExcelBinOutput/TpsWeaponExcelConfigData.json",
    "ExcelBinOutput/WeaponExcelConfigData.json",
];

fn main() -> io::Result<()> {
    generate_protos();

    println!("cargo:rerun-if-changed=build.rs");

    let manifest_dir = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::NotFound,
            "CARGO_MANIFEST_DIR was not set by cargo",
        )
    })?);
    let workspace_dir = manifest_dir.parent().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::NotFound,
            "pcap2good-core must be inside the workspace",
        )
    })?;
    let data_dir = workspace_dir.join(GAME_DATA_SUBDIR);
    let out_dir =
        PathBuf::from(env::var_os("OUT_DIR").ok_or_else(|| {
            io::Error::new(io::ErrorKind::NotFound, "OUT_DIR was not set by cargo")
        })?);

    if !data_dir.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!(
                "Genshin game data was not found at {}.\n\
                 Download Dimbreath's AnimeGameData dump before building:\n\
                 \n\
                 \x20 git clone --depth 1 https://gitlab.com/Dimbreath/animegamedata2 {GAME_DATA_SUBDIR}\n\
                 \n\
                 The directory is gitignored; an existing checkout may be moved or linked there instead.",
                data_dir.display()
            ),
        ));
    }

    for file in INPUT_FILES {
        println!("cargo:rerun-if-changed={}", data_dir.join(file).display());
    }

    let db = load_database(&data_dir)?;
    write_game_data(&db, &out_dir.join("game_data.gz"))?;

    Ok(())
}

/// Generates the Rust types for the game's protobuf messages.
fn generate_protos() {
    protobuf_codegen::Codegen::new()
        .pure()
        .cargo_out_dir("protos")
        .include("src/auto_artifactarium")
        .inputs([PROTO_INPUT])
        .run_from_script();

    println!("cargo:rerun-if-changed={PROTO_INPUT}");
}

/// The document consumed by the runtime (see `src/gamedata.rs`).
#[derive(Serialize)]
struct Database {
    affix_map: HashMap<u32, Affix>,
    artifact_map: HashMap<u32, Artifact>,
    character_map: HashMap<u32, String>,
    known_achievement_ids: HashSet<u32>,
    known_item_ids: HashSet<u32>,
    material_map: HashMap<u32, String>,
    property_map: HashMap<u32, Property>,
    skill_element_map: HashMap<u32, Element>,
    skill_type_map: HashMap<u32, SkillType>,
    tps_avatar_id_female: Option<u32>,
    tps_avatar_id_male: Option<u32>,
    weapon_map: HashMap<u32, Weapon>,
}

#[derive(Serialize)]
struct Affix {
    property: Property,
    value: f64,
}

#[derive(Serialize)]
struct Artifact {
    set: String,
    slot: ArtifactSlot,
    rarity: u32,
}

#[derive(Serialize)]
struct Weapon {
    name: String,
    rarity: u32,
}

#[derive(Clone, Copy, Serialize)]
enum Property {
    Hp,
    HpPercent,
    Attack,
    AttackPercent,
    Defense,
    DefensePercent,
    ElementalMastery,
    EnergyRecharge,
    Healing,
    CritRate,
    CritDamage,
    PhysicalDamage,
    AnemoDamage,
    GeoDamage,
    ElectroDamage,
    HydroDamage,
    PyroDamage,
    CryoDamage,
    DendroDamage,
}

impl Property {
    fn is_percentage(&self) -> bool {
        matches!(
            self,
            Property::HpPercent
                | Property::AttackPercent
                | Property::DefensePercent
                | Property::EnergyRecharge
                | Property::Healing
                | Property::CritRate
                | Property::CritDamage
                | Property::PhysicalDamage
                | Property::AnemoDamage
                | Property::GeoDamage
                | Property::ElectroDamage
                | Property::HydroDamage
                | Property::PyroDamage
                | Property::CryoDamage
                | Property::DendroDamage
        )
    }

    fn parse(name: &str) -> Option<Self> {
        Some(match name {
            "FIGHT_PROP_HP" => Self::Hp,
            "FIGHT_PROP_HP_PERCENT" => Self::HpPercent,
            "FIGHT_PROP_ATTACK" => Self::Attack,
            "FIGHT_PROP_ATTACK_PERCENT" => Self::AttackPercent,
            "FIGHT_PROP_DEFENSE" => Self::Defense,
            "FIGHT_PROP_DEFENSE_PERCENT" => Self::DefensePercent,
            "FIGHT_PROP_ELEMENT_MASTERY" => Self::ElementalMastery,
            "FIGHT_PROP_CHARGE_EFFICIENCY" => Self::EnergyRecharge,
            "FIGHT_PROP_HEAL_ADD" => Self::Healing,
            "FIGHT_PROP_CRITICAL" => Self::CritRate,
            "FIGHT_PROP_CRITICAL_HURT" => Self::CritDamage,
            "FIGHT_PROP_PHYSICAL_ADD_HURT" => Self::PhysicalDamage,
            "FIGHT_PROP_WIND_ADD_HURT" => Self::AnemoDamage,
            "FIGHT_PROP_ROCK_ADD_HURT" => Self::GeoDamage,
            "FIGHT_PROP_ELEC_ADD_HURT" => Self::ElectroDamage,
            "FIGHT_PROP_WATER_ADD_HURT" => Self::HydroDamage,
            "FIGHT_PROP_FIRE_ADD_HURT" => Self::PyroDamage,
            "FIGHT_PROP_ICE_ADD_HURT" => Self::CryoDamage,
            "FIGHT_PROP_GRASS_ADD_HURT" => Self::DendroDamage,
            _ => return None,
        })
    }
}

#[derive(Clone, Copy, Serialize)]
enum Element {
    Anemo,
    Geo,
    Electro,
    Hydro,
    Pyro,
    Cryo,
    Dendro,
}

impl Element {
    fn parse(name: &str) -> Option<Self> {
        Some(match name {
            "Wind" => Self::Anemo,
            "Rock" => Self::Geo,
            "Electric" => Self::Electro,
            "Water" => Self::Hydro,
            "Fire" => Self::Pyro,
            "Ice" => Self::Cryo,
            "Grass" => Self::Dendro,
            _ => return None,
        })
    }
}

#[derive(Clone, Copy, Serialize)]
enum ArtifactSlot {
    Flower,
    Plume,
    Sands,
    Goblet,
    Circlet,
}

impl ArtifactSlot {
    fn parse(name: &str) -> Option<Self> {
        Some(match name {
            "EQUIP_BRACER" => Self::Flower,
            "EQUIP_NECKLACE" => Self::Plume,
            "EQUIP_SHOES" => Self::Sands,
            "EQUIP_RING" => Self::Goblet,
            "EQUIP_DRESS" => Self::Circlet,
            _ => return None,
        })
    }
}

#[derive(Clone, Copy, Serialize)]
enum SkillType {
    Auto,
    Skill,
    Burst,
}

// Starting with the 7.0.0 data dump, fields holding their default value
// (0, false, "", or the first enum variant) are omitted from the JSON
// entirely. All fields are marked `#[serde(default)]` so entries missing them
// still deserialize, with optional id fields typed as `Option`.
mod excel {
    use serde::Deserialize;

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "camelCase")]
    pub struct Avatar {
        #[serde(default)]
        pub id: u32,
        #[serde(default)]
        pub name_text_map_hash: u32,
    }

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "camelCase")]
    pub struct AvatarSkillDepot {
        #[serde(default)]
        pub energy_skill: Option<u32>,
        #[serde(default)]
        skills: Vec<u32>,
    }

    impl AvatarSkillDepot {
        // Skill slots hold 0 as a placeholder for empty slots.
        pub fn skill(&self, index: usize) -> Option<u32> {
            self.skills.get(index).copied().filter(|&id| id != 0)
        }
    }

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "camelCase")]
    pub struct AvatarSkill {
        #[serde(default)]
        pub cost_elem_type: Option<String>,
        #[serde(default)]
        pub id: u32,
    }

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "camelCase")]
    pub struct ConstValue {
        #[serde(default)]
        pub name: String,
        #[serde(default)]
        pub value: Vec<String>,
    }

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "camelCase")]
    pub struct EquipAffix {
        #[serde(default)]
        pub id: u32,
        #[serde(default)]
        pub name_text_map_hash: u32,
    }

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "camelCase")]
    pub struct Material {
        #[serde(default)]
        pub id: u32,
        #[serde(default)]
        pub name_text_map_hash: u32,
    }

    #[derive(Debug, Deserialize)]
    pub struct IdEntry {
        #[serde(default)]
        pub id: u32,
    }

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "camelCase")]
    pub struct ReliquaryAffix {
        #[serde(default)]
        pub id: u32,
        #[serde(default)]
        pub prop_type: String,
        #[serde(default)]
        pub prop_value: f64,
    }

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "camelCase")]
    pub struct Reliquary {
        #[serde(default)]
        pub equip_type: String,
        #[serde(default)]
        pub id: u32,
        #[serde(default)]
        pub rank_level: u32,
        #[serde(default)]
        pub set_id: Option<u32>,
    }

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "camelCase")]
    pub struct ReliquaryMainProp {
        #[serde(default)]
        pub id: u32,
        #[serde(default)]
        pub prop_type: String,
    }

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "camelCase")]
    pub struct ReliquarySet {
        #[serde(default)]
        pub equip_affix_id: Option<u32>,
        #[serde(default)]
        pub set_id: u32,
    }

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "camelCase")]
    pub struct Weapon {
        #[serde(default)]
        pub id: u32,
        #[serde(default)]
        pub name_text_map_hash: u32,
        #[serde(default)]
        pub rank_level: u32,
    }
}

fn load_database(data_dir: &Path) -> io::Result<Database> {
    let text_map: HashMap<u32, String> = read_json(data_dir, "TextMap/TextMap_MediumEN.json")?;

    let affix_map = fetch_affix_map(data_dir)?;
    let set_map = fetch_set_map(data_dir, &text_map)?;
    let artifact_map = fetch_artifact_map(data_dir, &set_map)?;
    let property_map = fetch_property_map(data_dir)?;
    let weapon_map = fetch_weapon_map(data_dir, &text_map)?;
    let material_map = fetch_material_map(data_dir, &text_map)?;
    let character_map = fetch_character_map(data_dir, &text_map)?;
    let known_achievement_ids = fetch_known_achievement_ids(data_dir)?;
    let known_item_ids = fetch_known_item_ids(data_dir)?;
    let skill_element_map = fetch_skill_element_map(data_dir)?;
    let skill_type_map = fetch_skill_type_map(data_dir)?;

    let const_values: HashMap<String, Vec<String>> = read_json::<Vec<excel::ConstValue>>(
        data_dir,
        "ExcelBinOutput/ConstValueExcelConfigData.json",
    )?
    .into_iter()
    .map(|entry| (entry.name, entry.value))
    .collect();

    Ok(Database {
        affix_map,
        artifact_map,
        character_map,
        known_achievement_ids,
        known_item_ids,
        material_map,
        property_map,
        skill_element_map,
        skill_type_map,
        tps_avatar_id_female: lookup_const_value(
            &const_values,
            "CONST_VALUE_TPS_AVATAR_CONFIG_ID_FEMALE",
        ),
        tps_avatar_id_male: lookup_const_value(
            &const_values,
            "CONST_VALUE_TPS_AVATAR_CONFIG_ID_MALE",
        ),
        weapon_map,
    })
}

fn fetch_affix_map(data_dir: &Path) -> io::Result<HashMap<u32, Affix>> {
    let data: Vec<excel::ReliquaryAffix> = read_json(
        data_dir,
        "ExcelBinOutput/ReliquaryAffixExcelConfigData.json",
    )?;

    Ok(data
        .iter()
        .filter_map(|entry| {
            let property = Property::parse(&entry.prop_type)?;
            let value = if property.is_percentage() {
                entry.prop_value * 100.
            } else {
                entry.prop_value
            };
            Some((entry.id, Affix { property, value }))
        })
        .collect())
}

fn fetch_artifact_map(
    data_dir: &Path,
    set_map: &HashMap<u32, String>,
) -> io::Result<HashMap<u32, Artifact>> {
    let data: Vec<excel::Reliquary> =
        read_json(data_dir, "ExcelBinOutput/ReliquaryExcelConfigData.json")?;

    Ok(data
        .iter()
        .filter_map(|entry| {
            let set = set_map.get(&entry.set_id?)?.clone();
            let slot = ArtifactSlot::parse(&entry.equip_type)?;
            Some((
                entry.id,
                Artifact {
                    set,
                    slot,
                    rarity: entry.rank_level,
                },
            ))
        })
        .collect())
}

fn fetch_character_map(
    data_dir: &Path,
    text_map: &HashMap<u32, String>,
) -> io::Result<HashMap<u32, String>> {
    let data: Vec<excel::Avatar> =
        read_json(data_dir, "ExcelBinOutput/AvatarExcelConfigData.json")?;

    Ok(data
        .iter()
        .filter_map(|entry| Some((entry.id, text_map.get(&entry.name_text_map_hash)?.clone())))
        .collect())
}

fn fetch_material_map(
    data_dir: &Path,
    text_map: &HashMap<u32, String>,
) -> io::Result<HashMap<u32, String>> {
    let data: Vec<excel::Material> =
        read_json(data_dir, "ExcelBinOutput/MaterialExcelConfigData.json")?;

    Ok(data
        .iter()
        .filter_map(|entry| Some((entry.id, text_map.get(&entry.name_text_map_hash)?.clone())))
        .collect())
}

fn fetch_known_item_ids(data_dir: &Path) -> io::Result<HashSet<u32>> {
    let mut ids = HashSet::new();
    for relative in ITEM_ID_FILES {
        let entries: Vec<excel::IdEntry> = read_json(data_dir, relative)?;
        ids.extend(
            entries
                .into_iter()
                .map(|entry| entry.id)
                .filter(|id| *id != 0),
        );
    }
    Ok(ids)
}

fn fetch_known_achievement_ids(data_dir: &Path) -> io::Result<HashSet<u32>> {
    let entries: Vec<excel::IdEntry> =
        read_json(data_dir, "ExcelBinOutput/AchievementExcelConfigData.json")?;
    Ok(entries
        .into_iter()
        .map(|entry| entry.id)
        .filter(|id| *id != 0)
        .collect())
}

fn fetch_property_map(data_dir: &Path) -> io::Result<HashMap<u32, Property>> {
    let data: Vec<excel::ReliquaryMainProp> = read_json(
        data_dir,
        "ExcelBinOutput/ReliquaryMainPropExcelConfigData.json",
    )?;

    Ok(data
        .iter()
        .filter_map(|entry| Some((entry.id, Property::parse(&entry.prop_type)?)))
        .collect())
}

fn fetch_set_map(
    data_dir: &Path,
    text_map: &HashMap<u32, String>,
) -> io::Result<HashMap<u32, String>> {
    let affix_data: Vec<excel::EquipAffix> =
        read_json(data_dir, "ExcelBinOutput/EquipAffixExcelConfigData.json")?;

    // An affix has one entry per set bonus tier, all sharing the set's name.
    let affix_names: HashMap<u32, &String> = affix_data
        .iter()
        .filter_map(|entry| Some((entry.id, text_map.get(&entry.name_text_map_hash)?)))
        .collect();

    let set_data: Vec<excel::ReliquarySet> =
        read_json(data_dir, "ExcelBinOutput/ReliquarySetExcelConfigData.json")?;

    Ok(set_data
        .iter()
        .filter_map(|entry| {
            // Sets that grant no bonuses omit equipAffixId and have no name.
            let name = affix_names.get(&entry.equip_affix_id?)?.to_string();
            Some((entry.set_id, name))
        })
        .collect())
}

fn fetch_skill_element_map(data_dir: &Path) -> io::Result<HashMap<u32, Element>> {
    let data: Vec<excel::AvatarSkill> =
        read_json(data_dir, "ExcelBinOutput/AvatarSkillExcelConfigData.json")?;

    Ok(data
        .iter()
        .filter_map(|entry| {
            // Skills that cost no elemental energy omit costElemType and
            // have no element.
            let element = Element::parse(entry.cost_elem_type.as_ref()?)?;
            Some((entry.id, element))
        })
        .collect())
}

fn fetch_skill_type_map(data_dir: &Path) -> io::Result<HashMap<u32, SkillType>> {
    let data: Vec<excel::AvatarSkillDepot> = read_json(
        data_dir,
        "ExcelBinOutput/AvatarSkillDepotExcelConfigData.json",
    )?;

    let mut type_map = HashMap::new();
    for config in &data {
        // Depots without a burst (e.g. the elementless Traveler) have no
        // energy skill, and skill slots may be empty or missing.
        if let Some(skill) = config.energy_skill {
            type_map.insert(skill, SkillType::Burst);
        }
        if let Some(skill) = config.skill(0) {
            type_map.insert(skill, SkillType::Auto);
        }
        if let Some(skill) = config.skill(1) {
            type_map.insert(skill, SkillType::Skill);
        }
    }

    Ok(type_map)
}

fn fetch_weapon_map(
    data_dir: &Path,
    text_map: &HashMap<u32, String>,
) -> io::Result<HashMap<u32, Weapon>> {
    let data: Vec<excel::Weapon> =
        read_json(data_dir, "ExcelBinOutput/WeaponExcelConfigData.json")?;

    Ok(data
        .iter()
        .filter_map(|entry| {
            let name = text_map.get(&entry.name_text_map_hash)?.clone();
            Some((
                entry.id,
                Weapon {
                    name,
                    rarity: entry.rank_level,
                },
            ))
        })
        .collect())
}

fn lookup_const_value<T: FromStr>(
    const_values: &HashMap<String, Vec<String>>,
    name: &str,
) -> Option<T> {
    const_values.get(name)?.first()?.parse().ok()
}

fn read_json<T: DeserializeOwned>(data_dir: &Path, relative: &str) -> io::Result<T> {
    let path = data_dir.join(relative);
    let bytes = fs::read(&path)
        .map_err(|e| io::Error::new(e.kind(), format!("Failed to read {}: {e}", path.display())))?;

    serde_json::from_slice(&bytes).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("Failed to parse {}: {e}", path.display()),
        )
    })
}

fn write_game_data(db: &Database, path: &Path) -> io::Result<()> {
    let file = File::create(path)?;
    let mut writer = GzEncoder::new(file, Compression::best());
    serde_json::to_writer_pretty(&mut writer, db)
        .map_err(|e| io::Error::other(format!("Failed to write {}: {e}", path.display())))?;
    writer.finish()?;
    Ok(())
}

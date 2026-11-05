//! Offline game data lookups.
//!
//! Only the runtime half of `anime-game-data` lives here. Downloading and
//! normalizing the upstream game data happens at build time (see `build.rs`),
//! which serializes the same JSON document this module reads.
//!
//! Adapted from [`anime-game-data`], Copyright (c) 2025 Erik Gilling, MIT
//! licensed. The redundant network/update code and the fields this tool does
//! not use were left out.
//!
//! [`anime-game-data`]: https://github.com/konkers/anime-game-data

use std::collections::{HashMap, HashSet};
use std::io::Read;

use anyhow::{Result, anyhow};
use serde::Deserialize;

/// The document embedded by `build.rs` (see `game_data.gz`).
#[derive(Debug, Deserialize)]
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

#[derive(Debug)]
pub struct GameData {
    db: Database,
}

impl GameData {
    /// Parses the game data document embedded in the binary.
    pub fn from_reader<R: Read>(reader: R) -> Result<Self> {
        let db = serde_json::from_reader(reader)?;
        Ok(Self { db })
    }

    pub fn get_affix(&self, id: u32) -> Result<&Affix> {
        self.db
            .affix_map
            .get(&id)
            .ok_or_else(|| anyhow!("Unable to fetch affix {id}"))
    }

    pub fn get_artifact(&self, id: u32) -> Result<&Artifact> {
        self.db
            .artifact_map
            .get(&id)
            .ok_or_else(|| anyhow!("Unable to fetch artifact {id}"))
    }

    pub fn get_character(&self, id: u32) -> Result<&String> {
        self.db
            .character_map
            .get(&id)
            .ok_or_else(|| anyhow!("Unable to fetch character {id}"))
    }

    pub fn get_material(&self, id: u32) -> Result<&String> {
        self.db
            .material_map
            .get(&id)
            .ok_or_else(|| anyhow!("Unable to fetch material {id}"))
    }

    /// Whether `id` is an item id known from the embedded game data.
    pub fn is_known_item_id(&self, id: u32) -> bool {
        self.db.known_item_ids.contains(&id)
    }

    /// Whether `id` is an achievement id known from the embedded game data.
    pub fn is_known_achievement_id(&self, id: u32) -> bool {
        self.db.known_achievement_ids.contains(&id)
    }

    pub fn get_property(&self, id: u32) -> Result<&Property> {
        self.db
            .property_map
            .get(&id)
            .ok_or_else(|| anyhow!("Unable to fetch property {id}"))
    }

    pub fn get_skill_element(&self, id: u32) -> Result<&Element> {
        self.db
            .skill_element_map
            .get(&id)
            .ok_or_else(|| anyhow!("Unable to fetch skill element {id}"))
    }

    pub fn get_skill_type(&self, id: u32) -> Result<&SkillType> {
        self.db
            .skill_type_map
            .get(&id)
            .ok_or_else(|| anyhow!("Unable to fetch skill type {id}"))
    }

    pub fn get_tps_avatar_id_female(&self) -> Result<u32> {
        self.db
            .tps_avatar_id_female
            .ok_or_else(|| anyhow!("Unable to fetch female TPS avatar id"))
    }

    pub fn get_tps_avatar_id_male(&self) -> Result<u32> {
        self.db
            .tps_avatar_id_male
            .ok_or_else(|| anyhow!("Unable to fetch male TPS avatar id"))
    }

    pub fn get_weapon(&self, id: u32) -> Result<&Weapon> {
        self.db
            .weapon_map
            .get(&id)
            .ok_or_else(|| anyhow!("Unable to fetch weapon {id}"))
    }
}

#[derive(Debug, Deserialize, PartialEq)]
pub struct Affix {
    pub property: Property,
    pub value: f64,
}

#[derive(Debug, Deserialize, Eq, PartialEq)]
pub struct Artifact {
    pub set: String,
    pub slot: ArtifactSlot,
    pub rarity: u32,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
pub enum ArtifactSlot {
    Flower,
    Plume,
    Sands,
    Goblet,
    Circlet,
}

impl ArtifactSlot {
    pub fn good_name(&self) -> &str {
        match self {
            ArtifactSlot::Flower => "flower",
            ArtifactSlot::Plume => "plume",
            ArtifactSlot::Sands => "sands",
            ArtifactSlot::Goblet => "goblet",
            ArtifactSlot::Circlet => "circlet",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
pub enum Element {
    Anemo,
    Geo,
    Electro,
    Hydro,
    Pyro,
    Cryo,
    Dendro,
}

impl AsRef<str> for Element {
    fn as_ref(&self) -> &str {
        match self {
            Element::Anemo => "Anemo",
            Element::Geo => "Geo",
            Element::Electro => "Electro",
            Element::Hydro => "Hydro",
            Element::Pyro => "Pyro",
            Element::Cryo => "Cryo",
            Element::Dendro => "Dendro",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq)]
pub enum Property {
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
    pub fn good_name(&self) -> &str {
        match self {
            Property::Hp => "hp",
            Property::HpPercent => "hp_",
            Property::Attack => "atk",
            Property::AttackPercent => "atk_",
            Property::Defense => "def",
            Property::DefensePercent => "def_",
            Property::ElementalMastery => "eleMas",
            Property::EnergyRecharge => "enerRech_",
            Property::Healing => "heal_",
            Property::CritRate => "critRate_",
            Property::CritDamage => "critDMG_",
            Property::PhysicalDamage => "physical_dmg_",
            Property::AnemoDamage => "anemo_dmg_",
            Property::GeoDamage => "geo_dmg_",
            Property::ElectroDamage => "electro_dmg_",
            Property::HydroDamage => "hydro_dmg_",
            Property::PyroDamage => "pyro_dmg_",
            Property::CryoDamage => "cryo_dmg_",
            Property::DendroDamage => "dendro_dmg_",
        }
    }

    pub fn is_percentage(&self) -> bool {
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
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
pub enum SkillType {
    Auto,
    Skill,
    Burst,
}

#[derive(Debug, Deserialize)]
pub struct Weapon {
    pub name: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"{
        "version": 4,
        "git_hash": "test",
        "affix_map": { "501022": { "property": "Hp", "value": 239.0 } },
        "artifact_map": {
            "31534": {
                "set": "Marechaussee Hunter",
                "slot": "Circlet",
                "rarity": 5
            }
        },
        "character_map": { "10000061": "Kirara" },
        "known_achievement_ids": [80001, 80014],
        "known_item_ids": [100002, 11505, 31534],
        "material_map": { "100002": "Sunsettia" },
        "property_map": { "50960": "PyroDamage" },
        "set_map": {},
        "skill_element_map": { "10118": "Dendro" },
        "skill_type_map": { "10024": "Auto" },
        "tps_avatar_id_female": 10000135,
        "tps_avatar_id_male": 10000134,
        "weapon_map": { "11505": { "name": "Primordial Jade Cutter", "rarity": 5 } }
    }"#;

    fn sample() -> GameData {
        GameData::from_reader(SAMPLE.as_bytes()).unwrap()
    }

    #[test]
    fn lookups_match_the_embedded_schema() {
        let data = sample();

        assert_eq!(data.get_character(10000061).unwrap(), "Kirara");
        assert_eq!(data.get_material(100002).unwrap(), "Sunsettia");
        assert_eq!(
            data.get_weapon(11505).unwrap().name,
            "Primordial Jade Cutter"
        );
        assert_eq!(data.get_property(50960).unwrap(), &Property::PyroDamage);
        assert_eq!(data.get_skill_type(10024).unwrap(), &SkillType::Auto);
        assert_eq!(data.get_skill_element(10118).unwrap(), &Element::Dendro);
        assert_eq!(data.get_tps_avatar_id_female().unwrap(), 10000135);
        assert_eq!(data.get_tps_avatar_id_male().unwrap(), 10000134);
        assert!(data.is_known_item_id(100002));
        assert!(data.is_known_item_id(11505));
        assert!(data.is_known_item_id(31534));
        assert!(!data.is_known_item_id(999_999));
        assert!(data.is_known_achievement_id(80001));
        assert!(!data.is_known_achievement_id(999_999));

        let artifact = data.get_artifact(31534).unwrap();
        assert_eq!(artifact.set, "Marechaussee Hunter");
        assert_eq!(artifact.slot.good_name(), "circlet");
        assert_eq!(artifact.rarity, 5);

        let affix = data.get_affix(501022).unwrap();
        assert_eq!(affix.property, Property::Hp);
        assert_eq!(affix.value, 239.0);
    }

    #[test]
    fn unknown_ids_are_errors() {
        let data = sample();
        assert!(data.get_character(1).is_err());
        assert!(data.get_tps_avatar_id_female().is_ok());
    }

    #[test]
    fn properties_have_good_keys() {
        assert_eq!(Property::HpPercent.good_name(), "hp_");
        assert!(Property::HpPercent.is_percentage());
        assert!(!Property::Hp.is_percentage());
        assert_eq!(Element::Cryo.as_ref(), "Cryo");
    }
}

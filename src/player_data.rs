use std::collections::HashMap;

pub use crate::auto_artifactarium::r#gen::protos::{AvatarInfo, Item};
use indexmap::IndexMap;
use serde::{Deserialize, Serialize};

use crate::gamedata::{GameData, Property, SkillType};
use crate::good::{self, fake_uninitialized_4th_line};

/// `PROP_PLAYER_SCOIN`: the player's Mora balance, delivered in the player
/// property map (`PlayerDataNotify` / `PlayerPropNotify`) rather than in the
/// item store.
pub const PROP_PLAYER_SCOIN: u32 = 10016;

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default, rename_all = "camelCase")]
pub struct ExportSettings {
    pub fake_initialize_4th_line: bool,
}

pub struct PlayerData {
    game_data: GameData,
    characters: Vec<AvatarInfo>,
    items: Vec<Item>,
    player_props: HashMap<u32, i64>,

    character_equip_guid_map: HashMap<u64, u32>,
}

impl PlayerData {
    pub fn new(game_data: GameData) -> Self {
        Self {
            game_data,
            characters: Vec::new(),
            items: Vec::new(),
            player_props: HashMap::new(),
            character_equip_guid_map: HashMap::new(),
        }
    }

    pub fn process_characters(&mut self, avatars: &[AvatarInfo]) {
        self.character_equip_guid_map.clear();
        for avatar in avatars {
            for guid in &avatar.equip_guid_list {
                self.character_equip_guid_map
                    .insert(*guid, avatar.avatar_id);
            }
        }
        self.characters = avatars.into();
    }

    pub fn process_items(&mut self, items: &[Item]) {
        self.items = items.into();
    }

    pub fn process_player_props(&mut self, props: HashMap<u32, i64>) {
        // `PlayerPropNotify` only carries the properties that changed.
        self.player_props.extend(props);
    }

    pub fn export_genshin_optimizer(&self, settings: &ExportSettings) -> good::Good {
        let artifacts = self.export_genshin_optimizer_artifacts();

        good::Good {
            format: "GOOD".to_string(),
            version: 3,
            source: "post-irminsul".to_string(),
            characters: self.export_genshin_optimizer_characters(),
            artifacts: if settings.fake_initialize_4th_line {
                fake_uninitialized_4th_line(artifacts)
            } else {
                artifacts
            },
            weapons: self.export_genshin_optimizer_weapons(),
            materials: self.export_genshin_optimizer_materials(),
        }
    }

    pub fn export_genshin_optimizer_characters(&self) -> Vec<good::Character> {
        // TPS avatars are not normal characters and are excluded from export.
        let tps_avatar_ids: Vec<u32> = [
            self.game_data.get_tps_avatar_id_female(),
            self.game_data.get_tps_avatar_id_male(),
        ]
        .into_iter()
        .filter_map(Result::ok)
        .collect();

        self.characters
            .iter()
            .filter_map(|character| {
                if character.avatar_type != 1 || tps_avatar_ids.contains(&character.avatar_id) {
                    return None;
                }

                let name = self.game_data.get_character(character.avatar_id).ok()?;
                let level = character.prop_map.get(&4001).map(|prop| prop.val as u32)?;
                let ascension = character.prop_map.get(&1002).map(|prop| prop.val as u32)?;
                let constellation = character.talent_id_list.len() as u32;

                let mut auto = 1;
                let mut skill = 1;
                let mut burst = 1;
                let mut element = None;

                for (id, level) in &character.skill_level_map {
                    let Some(ty) = self.game_data.get_skill_type(*id).ok() else {
                        continue;
                    };
                    match ty {
                        SkillType::Auto => auto = *level,
                        SkillType::Skill => skill = *level,
                        SkillType::Burst => {
                            burst = *level;
                            element = self.game_data.get_skill_element(*id).ok().copied();
                        }
                    }
                }

                // The Traveler is the only character that can change elements.
                // The GOOD format lets you optionally suffix the Traveler's
                // name with their element (e.g. `TravelerCryo`).
                let mut key = good::to_good_key(name);
                if key == good::TRAVELER_KEY
                    && let Some(element) = element
                {
                    key.push_str(element.as_ref());
                }

                Some(good::Character {
                    key,
                    level,
                    constellation,
                    ascension,
                    talent: good::TalentLevel { auto, skill, burst },
                })
            })
            .collect()
    }

    pub fn round(property: Property, value: f32) -> f32 {
        // The game rounds percentages to 0.1 and non percentages to whole numbers.
        if property.is_percentage() {
            (value * 10.).round() / 10.
        } else {
            value.round()
        }
    }

    pub fn export_genshin_optimizer_artifacts(&self) -> Vec<good::Artifact> {
        self.items
            .iter()
            .filter_map(|item| {
                if !item.has_equip() {
                    return None;
                }
                let equip = item.equip();
                let location = self.location(item.guid);

                if !equip.has_reliquary() {
                    return None;
                }
                let artifact_data = self.game_data.get_artifact(item.item_id).ok()?;
                let artifact = equip.reliquary();
                let mut substats: IndexMap<Property, (f32, f32)> = IndexMap::new();
                for substat_id in artifact.append_prop_id_list.iter() {
                    let Some(substat) = self.game_data.get_affix(*substat_id).ok() else {
                        continue;
                    };
                    let entry = substats
                        .entry(substat.property)
                        .or_insert((0., substat.value as f32));
                    entry.0 += substat.value as f32;
                }
                let substats = substats
                    .into_iter()
                    .map(|(property, (value, initial_value))| good::Substat {
                        key: property.good_name().to_string(),
                        value: Self::round(property, value),
                        initial_value: Self::round(property, initial_value),
                    })
                    .collect();
                let unactivated_substats = artifact
                    .unactivated_prop_id_list
                    .iter()
                    .filter_map(|substat_id| {
                        let substat = self.game_data.get_affix(*substat_id).ok()?;
                        Some(good::Substat {
                            key: substat.property.good_name().to_string(),
                            value: Self::round(substat.property, substat.value as f32),
                            initial_value: Self::round(substat.property, substat.value as f32),
                        })
                    })
                    .collect();
                let total_rolls = artifact.append_prop_id_list.len() as u32;

                let level = artifact.level - 1;
                let rarity = artifact_data.rarity;
                let astral_mark = artifact.starred;
                let elixir_crafted = !artifact.elixer_choices.is_empty();
                let main_stat_key = self
                    .game_data
                    .get_property(artifact.main_prop_id)
                    .ok()?
                    .good_name()
                    .to_string();

                Some(good::Artifact {
                    set_key: good::to_good_key(&artifact_data.set),
                    slot_key: artifact_data.slot.good_name().to_string(),
                    level,
                    rarity,
                    main_stat_key,
                    location,
                    lock: equip.is_locked,
                    substats,
                    total_rolls,
                    astral_mark,
                    elixir_crafted,
                    unactivated_substats,
                })
            })
            .collect()
    }

    pub fn export_genshin_optimizer_weapons(&self) -> Vec<good::Weapon> {
        self.items
            .iter()
            .filter_map(|item| {
                if !item.has_equip() {
                    return None;
                }
                let equip = item.equip();
                let location = self.location(item.guid);
                if !equip.has_weapon() {
                    return None;
                }
                let weapon_data = self.game_data.get_weapon(item.item_id).ok()?;
                let weapon = equip.weapon();
                let refinement = weapon
                    .affix_map
                    .values()
                    .cloned()
                    .next()
                    .unwrap_or_default()
                    + 1;

                let level = weapon.level;
                let ascension = weapon.promote_level;

                Some(good::Weapon {
                    key: good::to_good_key(&weapon_data.name),
                    level,
                    ascension,
                    refinement,
                    location,
                    lock: equip.is_locked,
                })
            })
            .collect()
    }

    pub fn export_genshin_optimizer_materials(&self) -> HashMap<String, u32> {
        let mut materials: HashMap<String, u32> = self
            .items
            .iter()
            .filter_map(|item| {
                if !item.has_material() {
                    return None;
                }
                let material = item.material();
                let name = self.game_data.get_material(item.item_id).ok()?;

                Some((good::to_good_key(name), material.count))
            })
            .collect();

        // Mora is a virtual currency and never appears in the item store, so it
        // is sourced from the player property map instead.
        if let Some(&mora) = self.player_props.get(&PROP_PLAYER_SCOIN)
            && mora > 0
        {
            materials.insert("Mora".to_string(), mora.min(u32::MAX as i64) as u32);
        }

        materials
    }

    /// Name of the character an item is equipped to, if any.
    fn location(&self, guid: u64) -> String {
        self.character_equip_guid_map
            .get(&guid)
            .and_then(|id| {
                self.game_data
                    .get_character(*id)
                    .ok()
                    .map(|location| good::to_good_key(location))
            })
            .unwrap_or_default()
    }
}

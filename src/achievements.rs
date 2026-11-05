//! Content-based achievement extraction.
//!
//! The achievement packet is not recognised by command id or field number.
//! Instead, a repeated message field is treated as an achievement list when its
//! entries contain a field whose values are known achievement ids, another field
//! with status values (0-3), and optionally a finish timestamp.

use std::collections::{HashMap, HashSet};

use protobuf::Message;
use protobuf::UnknownValueRef;
use serde::Serialize;

use crate::auto_artifactarium::r#gen::protos::Unk;
use crate::gamedata::GameData;

/// Achievements with this status or higher are finished (`2`) or claimed (`3`).
const COMPLETED_STATUS: u32 = 2;

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Achievement {
    pub id: u32,
    pub status: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub finish_timestamp: Option<u32>,
}

/// Achievements collected from one flow or the whole capture.
#[derive(Clone, Debug, Default, Serialize)]
pub struct AchievementStore {
    pub achievements: Vec<Achievement>,
    #[serde(skip)]
    index: HashMap<u32, usize>,
}

impl AchievementStore {
    pub fn merge(&mut self, achievements: &[Achievement]) {
        for achievement in achievements {
            match self.index.get(&achievement.id).copied() {
                Some(index) => {
                    let existing = &mut self.achievements[index];
                    if achievement.status >= existing.status {
                        *existing = achievement.clone();
                    }
                }
                None => {
                    self.index.insert(achievement.id, self.achievements.len());
                    self.achievements.push(achievement.clone());
                }
            }
        }
    }

    /// Finished or claimed achievement ids, sorted for a stable export.
    pub fn completed_ids(&self) -> Vec<u32> {
        let mut ids: Vec<u32> = self
            .achievements
            .iter()
            .filter(|achievement| achievement.status >= COMPLETED_STATUS)
            .map(|achievement| achievement.id)
            .collect();
        ids.sort_unstable();
        ids.dedup();
        ids
    }
}

/// The file format used by stardb.gg's importer.
#[derive(Clone, Debug, Default, Serialize)]
pub struct AchievementExport {
    pub gi_achievements: Vec<u32>,
}

impl AchievementExport {
    pub fn from_store(store: &AchievementStore) -> Self {
        Self {
            gi_achievements: store.completed_ids(),
        }
    }
}

/// Extracts an achievement list from a command body.
pub fn matches_achievement_packet(data: &[u8], game_data: &GameData) -> Option<Vec<Achievement>> {
    let packet = Unk::parse_from_bytes(data).ok()?;

    // Top-level field number -> the messages stored under it.
    let mut candidates: HashMap<u32, Vec<HashMap<u32, u64>>> = HashMap::new();
    for (field_number, field_data) in packet.unknown_fields().iter() {
        let UnknownValueRef::LengthDelimited(bytes) = field_data else {
            continue;
        };
        let Ok(inner) = Unk::parse_from_bytes(bytes) else {
            continue;
        };

        let mut fields = HashMap::new();
        let mut all_varint = true;
        for (inner_field, inner_value) in inner.unknown_fields().iter() {
            match inner_value {
                UnknownValueRef::Varint(value) => {
                    fields.insert(inner_field, value);
                }
                _ => {
                    all_varint = false;
                    break;
                }
            }
        }

        // Achievement entries have several scalar fields.
        if all_varint && fields.len() >= 2 {
            candidates.entry(field_number).or_default().push(fields);
        }
    }

    let mut best: Option<((usize, usize), Vec<Achievement>)> = None;
    for entries in candidates.into_values() {
        if entries.len() < 10 {
            continue;
        }

        let Some((id_tag, id_hits)) = best_id_tag(&entries, game_data) else {
            continue;
        };
        // Allow a few achievements from a newer game version to be unknown.
        if id_hits * 10 < entries.len() * 9 {
            continue;
        }

        let Some(status_tag) = best_status_tag(&entries, id_tag) else {
            continue;
        };
        let timestamp_tag = best_timestamp_tag(&entries, id_tag, status_tag);

        let achievements: Vec<Achievement> = entries
            .iter()
            .map(|entry| {
                let id = entry
                    .get(&id_tag)
                    .and_then(|value| u32::try_from(*value).ok())
                    .unwrap_or_default();
                let status = entry
                    .get(&status_tag)
                    .and_then(|value| u32::try_from(*value).ok())
                    .unwrap_or_default();
                let finish_timestamp = timestamp_tag
                    .and_then(|tag| entry.get(&tag))
                    .and_then(|value| u32::try_from(*value).ok());
                Achievement {
                    id,
                    status,
                    finish_timestamp,
                }
            })
            .collect();

        let score = (id_hits, entries.len());
        if best
            .as_ref()
            .is_none_or(|(best_score, _)| score > *best_score)
        {
            best = Some((score, achievements));
        }
    }

    best.map(|(_, achievements)| achievements)
}

fn best_id_tag(entries: &[HashMap<u32, u64>], game_data: &GameData) -> Option<(u32, usize)> {
    let mut hits: HashMap<u32, usize> = HashMap::new();
    for entry in entries {
        for (&tag, &value) in entry {
            if let Ok(id) = u32::try_from(value)
                && game_data.is_known_achievement_id(id)
            {
                *hits.entry(tag).or_default() += 1;
            }
        }
    }

    hits.into_iter().max_by_key(|(_, hits)| *hits)
}

fn best_status_tag(entries: &[HashMap<u32, u64>], id_tag: u32) -> Option<u32> {
    let tags: HashSet<u32> = entries
        .iter()
        .flat_map(|entry| entry.keys().copied())
        .collect();

    let mut best: Option<((usize, usize), u32)> = None;
    for tag in tags {
        if tag == id_tag {
            continue;
        }

        let mut present = 0;
        let mut completed = 0;
        let mut valid = true;
        for entry in entries {
            if let Some(&value) = entry.get(&tag) {
                present += 1;
                if value > 3 {
                    valid = false;
                    break;
                }
                if value >= u64::from(COMPLETED_STATUS) {
                    completed += 1;
                }
            }
        }

        if !valid || completed == 0 {
            continue;
        }

        let score = (completed, present);
        if best
            .as_ref()
            .is_none_or(|(best_score, _)| score > *best_score)
        {
            best = Some((score, tag));
        }
    }

    best.map(|(_, tag)| tag)
}

fn best_timestamp_tag(entries: &[HashMap<u32, u64>], id_tag: u32, status_tag: u32) -> Option<u32> {
    let tags: HashSet<u32> = entries
        .iter()
        .flat_map(|entry| entry.keys().copied())
        .collect();

    let mut best: Option<((usize, usize), u32)> = None;
    for tag in tags {
        if tag == id_tag || tag == status_tag {
            continue;
        }

        let mut present = 0;
        let mut timestamps = 0;
        let mut valid = true;
        for entry in entries {
            if let Some(&value) = entry.get(&tag) {
                present += 1;
                if value == 0 {
                    continue;
                }
                if !(1_000_000_000..=4_102_444_800).contains(&value) {
                    valid = false;
                    break;
                }
                timestamps += 1;
            }
        }

        if !valid || timestamps == 0 {
            continue;
        }

        let score = (timestamps, present);
        if best
            .as_ref()
            .is_none_or(|(best_score, _)| score > *best_score)
        {
            best = Some((score, tag));
        }
    }

    best.map(|(_, tag)| tag)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn achievement(id: u32, status: u32) -> Achievement {
        Achievement {
            id,
            status,
            finish_timestamp: None,
        }
    }

    #[test]
    fn merges_and_exports_only_completed_achievements() {
        let mut store = AchievementStore::default();
        store.merge(&[
            achievement(80001, 1),
            achievement(80002, 2),
            achievement(80003, 3),
        ]);
        store.merge(&[achievement(80001, 3)]);

        assert_eq!(store.completed_ids(), vec![80001, 80002, 80003]);
    }
}

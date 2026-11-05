use std::collections::HashMap;

use base64::Engine;
use base64::prelude::BASE64_STANDARD;
use protobuf::Message;
use protobuf::UnknownValueRef::*;
use rsa::{Pkcs1v15Encrypt, RsaPrivateKey};

use crate::gamedata::GameData;

use super::r#gen::protos::AvatarInfo;
use super::r#gen::protos::Item;
use super::r#gen::protos::PropMapEntry;
use super::r#gen::protos::Unk;

pub fn matches_get_player_token_rsp(
    data: Vec<u8>,
    rsa_keys: Vec<RsaPrivateKey>,
) -> Option<Vec<u64>> {
    let d_msg = Unk::parse_from_bytes(&data);
    match d_msg {
        Ok(d_msg) => {
            let mut to_ret: Vec<u64> = vec![];
            let unknown_fields = d_msg.unknown_fields();
            for (field_number, field_data) in unknown_fields.iter() {
                tracing::debug!("field: {}: {:?}", field_number, field_data);
                let possible_encrypted = match field_data {
                    LengthDelimited(encrypted_bytes) => {
                        let encrypted = BASE64_STANDARD.decode(encrypted_bytes);
                        match encrypted {
                            Ok(encrypted) => Some(encrypted),
                            _ => None,
                        }
                    }
                    _ => None,
                };
                let possible_seeds: Vec<u64> = match possible_encrypted {
                    Some(possible_encrypted) => rsa_keys
                        .iter()
                        .filter_map(|key| key.decrypt(Pkcs1v15Encrypt, &possible_encrypted).ok())
                        .collect::<Vec<Vec<u8>>>()
                        .iter()
                        .filter(|&seed| seed.len() == 8)
                        .map(|seed| u64::from_be_bytes(seed.as_slice().try_into().unwrap()))
                        .collect(),
                    _ => vec![],
                };
                to_ret.extend(possible_seeds)
            }
            if to_ret.len() != 0 {
                Some(to_ret)
            } else {
                None
            }
        }
        _ => None,
    }
}

/// Recognises a `PacketWithItems`-shaped packet by content rather than by
/// command id or field number.
///
/// A candidate field must hold at least ten items and at least 90% of those
/// items must have an id known from the embedded game data. Unknown ids are
/// tolerated because a capture may come from a newer game version than the
/// bundled data.
pub fn matches_items_all_data_notify(data: &[u8], game_data: &GameData) -> Option<Vec<Item>> {
    let packet = Unk::parse_from_bytes(data).ok()?;

    // `Some` means every entry seen for this field is a valid Item so far;
    // `None` means the field is not an item list.
    let mut candidates: HashMap<u32, Option<Vec<Item>>> = HashMap::new();
    for (field_number, field_data) in packet.unknown_fields().iter() {
        let LengthDelimited(bytes) = field_data else {
            continue;
        };

        let candidate = candidates
            .entry(field_number)
            .or_insert_with(|| Some(Vec::new()));
        match Item::parse_from_bytes(bytes) {
            Ok(item) if item.item_id != 0 && item.guid != 0 => {
                if let Some(items) = candidate {
                    items.push(item);
                }
            }
            // Empty/default entries are placeholders, not a reason to reject
            // the whole field.
            Ok(_) => {}
            Err(_) => *candidate = None,
        }
    }

    candidates
        .into_iter()
        .filter_map(|(_, items)| items)
        .filter(|items| {
            let known = items
                .iter()
                .filter(|item| game_data.is_known_item_id(item.item_id))
                .count();
            items.len() >= 10 && known * 10 >= items.len() * 9
        })
        .max_by_key(|items| items.len())
}

/// Recognises an `AvatarDataNotify`-shaped packet by content rather than by
/// command id or field number.
///
/// The packet must contain a length-delimited field whose repeated entries all
/// decode as [`AvatarInfo`] with a player avatar id and a non-zero guid. Both the
/// command id and the field number are reshuffled between game versions, while
/// player avatar ids stay in a stable range.
pub fn matches_avatars_all_data_notify(data: &[u8]) -> Option<Vec<AvatarInfo>> {
    let packet = Unk::parse_from_bytes(data).ok()?;

    // `Some` means every entry seen for this field is a valid avatar so far;
    // `None` means the field is not an avatar list.
    let mut candidates: HashMap<u32, Option<Vec<AvatarInfo>>> = HashMap::new();
    for (field_number, field_data) in packet.unknown_fields().iter() {
        let LengthDelimited(bytes) = field_data else {
            continue;
        };

        let candidate = candidates
            .entry(field_number)
            .or_insert_with(|| Some(Vec::new()));
        match AvatarInfo::parse_from_bytes(bytes) {
            Ok(avatar) if is_player_avatar(&avatar) => {
                if let Some(avatars) = candidate {
                    avatars.push(avatar);
                }
            }
            _ => *candidate = None,
        }
    }

    candidates
        .into_iter()
        .filter_map(|(_, avatars)| avatars)
        .filter(|avatars| !avatars.is_empty())
        .max_by_key(|avatars| avatars.len())
}

fn is_player_avatar(avatar: &AvatarInfo) -> bool {
    (10_000_000..=10_000_999).contains(&avatar.avatar_id)
        && avatar.guid != 0
        // Character items use the same id range, but an item has no avatar
        // property map. Requiring one keeps item packets from looking like
        // avatar lists once the command id is no longer available.
        && !avatar.prop_map.is_empty()
}

/// `PROP_PLAYER_SCOIN`: the player's Mora balance.
const PROP_PLAYER_SCOIN: u32 = 10016;

/// Extract the player property map carried by `PlayerDataNotify` (on login) and
/// `PlayerPropNotify` (whenever a property changes).
///
/// The packet is recognised by content rather than by command id or field
/// number, since both are reshuffled every game version. Player property ids
/// (`PROP_PLAYER_*`, 10000-10999) are stable, and genuine entries repeat their
/// key in `PropValue.type`, which unrelated fields practically never do.
pub fn matches_player_prop_map(data: &[u8]) -> Option<HashMap<u32, i64>> {
    let d_msg = Unk::parse_from_bytes(data).ok()?;
    let mut props: HashMap<u32, i64> = HashMap::new();
    let mut map_tag: Option<u32> = None;
    for (field_number, field_data) in d_msg.unknown_fields().iter() {
        let LengthDelimited(bytes) = field_data else {
            continue;
        };
        let Ok(entry) = PropMapEntry::parse_from_bytes(bytes) else {
            continue;
        };
        if !(10000..11000).contains(&entry.key) || entry.value.type_ != entry.key {
            continue;
        }
        // All entries of one map share a field number.
        if *map_tag.get_or_insert(field_number) != field_number {
            return None;
        }
        // `val` carries the current amount; fall back to the `ival` oneof for
        // entries that only populate the older field.
        let value = if entry.value.val != 0 {
            entry.value.val
        } else {
            entry.value.ival()
        };
        props.insert(entry.key, value);
    }

    // Only report packets that carry Mora, so frequent unrelated prop updates
    // (stamina and the like) don't register as new data.
    if !props.contains_key(&PROP_PLAYER_SCOIN) {
        return None;
    }

    Some(props)
}

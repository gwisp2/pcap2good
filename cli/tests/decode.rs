use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use base64::prelude::*;
use pcap2good_core::auto_artifactarium::r#gen::protos::{
    AvatarDataNotify, AvatarInfo, Equip, Item, Material, PacketWithItems, PropMapEntry, PropValue,
    Reliquary, Weapon, equip, item,
};
use pcap2good_core::decode::Decoder;
use pcap2good_core::pipeline::{CapturedFrame, LinkType, Timestamp};
use pcap2good_core::player_data::PROP_PLAYER_SCOIN;
use protobuf::Message;

const ETHERNET_HEADER_LEN: usize = 14;
const ETHERTYPE_IPV4: u16 = 0x0800;

const PLAYER_STORE_NOTIFY: u16 = 20892;
const AVATAR_DATA_NOTIFY: u16 = 20143;
const PLAYER_PROP_NOTIFY: u16 = 130;

const ARTIFACT_ITEM_ID: u32 = 31534; // Marechaussee Hunter circlet, 5 stars.
const WEAPON_ITEM_ID: u32 = 11505; // Primordial Jade Cutter, 5 stars.
const MATERIAL_ITEM_ID: u32 = 100002; // Sunsettia.
const CHARACTER_ID: u32 = 10000061; // Kirara.

const ARTIFACT_GUID: u64 = 1;
const WEAPON_GUID: u64 = 2;

fn encryption_key() -> Vec<u8> {
    let keys: BTreeMap<String, String> =
        serde_json::from_slice(include_bytes!("../../core/keys/gi.json")).unwrap();
    let encoded = keys.values().next().expect("at least one key");
    BASE64_STANDARD.decode(encoded).unwrap()
}

fn xor(data: &mut [u8], key: &[u8]) {
    for (i, byte) in data.iter_mut().enumerate() {
        *byte ^= key[i % key.len()];
    }
}

/// Wraps a protobuf payload in the game's command framing and encrypts it.
fn game_command(command_id: u16, proto: Vec<u8>) -> Vec<u8> {
    game_command_with_header(command_id, &[], &proto)
}

/// Like [`game_command`], but with explicit PacketHead bytes.
fn game_command_with_header(command_id: u16, header: &[u8], body: &[u8]) -> Vec<u8> {
    let mut command = Vec::new();
    command.extend_from_slice(&[0x45, 0x67]);
    command.extend_from_slice(&command_id.to_be_bytes());
    command.extend_from_slice(&(header.len() as u16).to_be_bytes());
    command.extend_from_slice(&(body.len() as u32).to_be_bytes());
    command.extend_from_slice(header);
    command.extend_from_slice(body);
    command.extend_from_slice(&[0x89, 0xab]);

    let key = encryption_key();
    xor(&mut command, &key);
    command
}

/// Wraps a command in a KCP segment using the game's slightly modified layout.
fn kcp_segment(sequence: u32, content: &[u8]) -> Vec<u8> {
    let mut segment = Vec::new();
    segment.extend_from_slice(&1u32.to_le_bytes()); // conversation id
    segment.extend_from_slice(&[0; 4]); // game specific padding
    segment.push(81); // command: push
    segment.push(0); // fragment: last
    segment.extend_from_slice(&1024u16.to_le_bytes()); // window
    segment.extend_from_slice(&0u32.to_le_bytes()); // timestamp
    segment.extend_from_slice(&sequence.to_le_bytes());
    segment.extend_from_slice(&0u32.to_le_bytes()); // unacknowledged
    segment.extend_from_slice(&(content.len() as u32).to_le_bytes());
    segment.extend_from_slice(&[0; 4]); // game specific padding
    segment.extend_from_slice(content);
    segment
}

fn udp_packet(payload: &[u8]) -> Vec<u8> {
    udp_packet_for_client(40000, payload)
}

fn udp_packet_for_client(client_port: u16, payload: &[u8]) -> Vec<u8> {
    let udp_len = 8 + payload.len();
    let total_len = 20 + udp_len;

    let mut packet = vec![0x45, 0x00];
    packet.extend_from_slice(&(total_len as u16).to_be_bytes());
    packet.extend_from_slice(&[0, 0, 0, 0]);
    packet.extend_from_slice(&[64, 17, 0, 0]);
    packet.extend_from_slice(&[10, 0, 0, 2]); // server
    packet.extend_from_slice(&[10, 0, 0, 1]); // client
    packet.extend_from_slice(&22101u16.to_be_bytes());
    packet.extend_from_slice(&client_port.to_be_bytes());
    packet.extend_from_slice(&(udp_len as u16).to_be_bytes());
    packet.extend_from_slice(&[0, 0]);
    packet.extend_from_slice(payload);
    packet
}

fn ethernet_frame(payload: &[u8]) -> Vec<u8> {
    let mut frame = vec![0; 12];
    frame.extend_from_slice(&ETHERTYPE_IPV4.to_be_bytes());
    frame.extend_from_slice(payload);
    frame
}

fn write_pcap(path: &Path, frames: &[Vec<u8>]) {
    fs::write(path, pcap_bytes(frames)).unwrap();
}

fn pcap_bytes(frames: &[Vec<u8>]) -> Vec<u8> {
    let mut file = Vec::new();
    file.extend_from_slice(&0xa1b2_c3d4u32.to_le_bytes());
    file.extend_from_slice(&2u16.to_le_bytes());
    file.extend_from_slice(&4u16.to_le_bytes());
    file.extend_from_slice(&0i32.to_le_bytes());
    file.extend_from_slice(&0u32.to_le_bytes());
    file.extend_from_slice(&65535u32.to_le_bytes());
    file.extend_from_slice(&1i32.to_le_bytes()); // LINKTYPE_ETHERNET

    for frame in frames {
        file.extend_from_slice(&0u32.to_le_bytes());
        file.extend_from_slice(&0u32.to_le_bytes());
        file.extend_from_slice(&(frame.len() as u32).to_le_bytes());
        file.extend_from_slice(&(frame.len() as u32).to_le_bytes());
        file.extend_from_slice(frame);
    }

    file
}

fn prop(value: i64) -> PropValue {
    PropValue {
        val: value,
        ..Default::default()
    }
}

fn character_message() -> Vec<u8> {
    character_message_with(90)
}

fn character_avatar(avatar_id: u32, guid: u64, level: i64) -> AvatarInfo {
    let mut avatar = AvatarInfo::new();
    avatar.avatar_id = avatar_id;
    avatar.guid = guid;
    avatar.avatar_type = 1;
    avatar.prop_map.insert(4001, prop(level)); // level
    avatar.prop_map.insert(1002, prop(6)); // ascension
    avatar.talent_id_list.extend_from_slice(&[0, 1, 2]); // constellation 3
    avatar.skill_level_map.insert(10024, 10); // normal attack
    avatar.skill_level_map.insert(10018, 10); // elemental skill
    avatar.skill_level_map.insert(10019, 10); // elemental burst
    avatar.equip_guid_list.push(ARTIFACT_GUID);
    avatar.equip_guid_list.push(WEAPON_GUID);
    avatar
}

fn character_message_with(level: i64) -> Vec<u8> {
    let mut notify = AvatarDataNotify::new();
    notify
        .avatar_list
        .push(character_avatar(CHARACTER_ID, 100, level));
    notify.write_to_bytes().unwrap()
}

fn write_varint(out: &mut Vec<u8>, mut value: u64) {
    while value >= 0x80 {
        out.push((value as u8) | 0x80);
        value >>= 7;
    }
    out.push(value as u8);
}

fn write_message_field(out: &mut Vec<u8>, field_number: u32, bytes: &[u8]) {
    write_varint(out, (u64::from(field_number) << 3) | 2);
    write_varint(out, bytes.len() as u64);
    out.extend_from_slice(bytes);
}

/// Builds a packet body with `messages` under an arbitrary top-level field.
fn message_list_with_field<T: Message>(field_number: u32, messages: &[T]) -> Vec<u8> {
    let mut body = Vec::new();
    for message in messages {
        write_message_field(&mut body, field_number, &message.write_to_bytes().unwrap());
    }
    body
}

fn avatar_list_with_field(field_number: u32, avatars: &[AvatarInfo]) -> Vec<u8> {
    message_list_with_field(field_number, avatars)
}

fn write_varint_field(out: &mut Vec<u8>, field_number: u32, value: u64) {
    write_varint(out, u64::from(field_number) << 3);
    write_varint(out, value);
}

fn achievement_entry(id: u32, status: u32, finish_timestamp: Option<u32>) -> Vec<u8> {
    let mut entry = Vec::new();
    if let Some(timestamp) = finish_timestamp {
        write_varint_field(&mut entry, 4, u64::from(timestamp));
    }
    write_varint_field(&mut entry, 7, u64::from(status));
    write_varint_field(&mut entry, 8, 1);
    write_varint_field(&mut entry, 9, u64::from(id));
    entry
}

fn raw_list_with_field(field_number: u32, messages: &[Vec<u8>]) -> Vec<u8> {
    let mut body = Vec::new();
    for message in messages {
        write_message_field(&mut body, field_number, message);
    }
    body
}

fn artifact_item() -> Item {
    let reliquary = Reliquary {
        level: 20,
        main_prop_id: 50960,                       // Pyro damage bonus
        append_prop_id_list: vec![501022, 501022], // flat HP
        ..Default::default()
    };

    let equip = Equip {
        is_locked: true,
        detail: Some(equip::Detail::Reliquary(reliquary)),
        ..Default::default()
    };

    Item {
        item_id: ARTIFACT_ITEM_ID,
        guid: ARTIFACT_GUID,
        detail: Some(item::Detail::Equip(equip)),
        ..Default::default()
    }
}

fn weapon_item() -> Item {
    let weapon = Weapon {
        level: 90,
        promote_level: 6,
        affix_map: [(5, 0)].into(),
        ..Default::default()
    };

    let equip = Equip {
        detail: Some(equip::Detail::Weapon(weapon)),
        ..Default::default()
    };

    Item {
        item_id: WEAPON_ITEM_ID,
        guid: WEAPON_GUID,
        detail: Some(item::Detail::Equip(equip)),
        ..Default::default()
    }
}

fn material_item(guid: u64, count: u32) -> Item {
    Item {
        item_id: MATERIAL_ITEM_ID,
        guid,
        detail: Some(item::Detail::Material(Material {
            count,
            ..Default::default()
        })),
        ..Default::default()
    }
}

fn unknown_item(guid: u64) -> Item {
    Item {
        item_id: 0xDEAD_BEEF,
        guid,
        detail: Some(item::Detail::Material(Material {
            count: 1,
            ..Default::default()
        })),
        ..Default::default()
    }
}

/// A full inventory: artifact, weapon, and ten materials.
fn inventory_items() -> Vec<Item> {
    let mut items = vec![artifact_item(), weapon_item()];
    for i in 0..10 {
        items.push(material_item(100 + i, 1));
    }
    items
}

fn items_message() -> Vec<u8> {
    let mut packet = PacketWithItems::new();
    packet.items.extend(inventory_items());
    packet.write_to_bytes().unwrap()
}

fn mora_message(mora: i64) -> Vec<u8> {
    let mut entry = PropMapEntry::new();
    entry.key = PROP_PLAYER_SCOIN;
    entry.value = protobuf::MessageField::some(PropValue {
        type_: PROP_PLAYER_SCOIN,
        val: mora,
        ..Default::default()
    });

    let entry = entry.write_to_bytes().unwrap();
    debug_assert!(entry.len() < 0x80);

    // The field number is arbitrary: the matcher locates the player prop map
    // by content rather than by field number.
    let mut body = Vec::new();
    body.push((3 << 3) | 2); // field 3, length-delimited
    body.push(entry.len() as u8);
    body.extend_from_slice(&entry);
    body
}

fn capture_with_game_data() -> Vec<Vec<u8>> {
    let commands = [
        game_command(AVATAR_DATA_NOTIFY, character_message()),
        game_command(PLAYER_STORE_NOTIFY, items_message()),
        game_command(PLAYER_PROP_NOTIFY, mora_message(123_456)),
    ];

    commands
        .iter()
        .enumerate()
        .map(|(i, command)| ethernet_frame(&udp_packet(&kcp_segment(i as u32, command))))
        .collect()
}

fn handshake_frame(client_port: u16) -> Vec<u8> {
    ethernet_frame(&udp_packet_for_client(client_port, &[0, 0, 0, 0xff]))
}

fn avatar_frame(client_port: u16, sequence: u32, level: i64) -> Vec<u8> {
    ethernet_frame(&udp_packet_for_client(
        client_port,
        &kcp_segment(
            sequence,
            &game_command(AVATAR_DATA_NOTIFY, character_message_with(level)),
        ),
    ))
}

fn content_frame(command_id: u16, body: Vec<u8>) -> Vec<u8> {
    ethernet_frame(&udp_packet_for_client(
        40000,
        &kcp_segment(0, &game_command(command_id, body)),
    ))
}

fn run_cli(path: &Path, extra_args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_pcap2good"))
        .arg("decode")
        .arg(path)
        .args(extra_args)
        .output()
        .unwrap()
}

fn temp_capture(name: &str, frames: &[Vec<u8>]) -> PathBuf {
    let path = std::env::temp_dir().join(format!(
        "pcap2good-it-{}-{name}.pcap",
        std::process::id()
    ));
    write_pcap(&path, frames);
    path
}

#[test]
fn decodes_characters_weapons_and_artifacts() {
    let path = temp_capture("good", &capture_with_game_data());
    let output = run_cli(&path, &[]);
    fs::remove_file(&path).ok();

    assert!(
        output.status.success(),
        "decode failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let good: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap_or_else(|e| {
        panic!(
            "stdout is not valid JSON ({e}): {}",
            String::from_utf8_lossy(&output.stdout)
        )
    });

    assert_eq!(good["format"], "GOOD");
    assert_eq!(good["version"], 3);
    assert_eq!(good["source"], "pcap2good");

    let characters = good["characters"].as_array().unwrap();
    assert_eq!(characters.len(), 1, "characters: {characters:?}");
    let character = &characters[0];
    assert_eq!(character["key"], "Kirara");
    assert_eq!(character["level"], 90);
    assert_eq!(character["ascension"], 6);
    assert_eq!(character["constellation"], 3);
    assert_eq!(character["talent"]["auto"], 10);
    assert_eq!(character["talent"]["skill"], 10);
    assert_eq!(character["talent"]["burst"], 10);

    let weapons = good["weapons"].as_array().unwrap();
    assert_eq!(weapons.len(), 1, "weapons: {weapons:?}");
    let weapon = &weapons[0];
    assert_eq!(weapon["key"], "PrimordialJadeCutter");
    assert_eq!(weapon["level"], 90);
    assert_eq!(weapon["ascension"], 6);
    assert_eq!(weapon["refinement"], 1);
    assert_eq!(weapon["location"], "Kirara");

    let artifacts = good["artifacts"].as_array().unwrap();
    assert_eq!(artifacts.len(), 1, "artifacts: {artifacts:?}");
    let artifact = &artifacts[0];
    assert_eq!(artifact["setKey"], "MarechausseeHunter");
    assert_eq!(artifact["slotKey"], "circlet");
    assert_eq!(artifact["level"], 19);
    assert_eq!(artifact["rarity"], 5);
    assert_eq!(artifact["mainStatKey"], "pyro_dmg_");
    assert_eq!(artifact["location"], "Kirara");
    assert_eq!(artifact["lock"], true);
    let substats = artifact["substats"].as_array().unwrap();
    assert_eq!(substats.len(), 1, "substats: {substats:?}");
    assert_eq!(substats[0]["key"], "hp");
    assert_eq!(substats[0]["value"], 478.0);

    // Materials are exported too.
    assert_eq!(good["materials"]["Sunsettia"], 1);
    assert_eq!(good["materials"]["Mora"], 123_456);

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("Exported 1 characters, 1 artifacts, 1 weapons"),
        "unexpected stderr: {stderr}"
    );
}

#[test]
fn live_snapshot_updates_without_finishing_the_decoder() {
    let frames = capture_with_game_data();
    let mut decoder = Decoder::new().unwrap();

    for (index, frame) in frames.iter().enumerate() {
        decoder.process_frame(CapturedFrame {
            timestamp: Timestamp::from_parts(0, index as u32 * 1_000),
            link_type: LinkType(1),
            data: frame.clone(),
        });
    }

    let snapshot = pcap2good_core::snapshot_outcome(decoder.snapshot());
    assert_eq!(snapshot.capture.packets, frames.len() as u64);
    assert_eq!(snapshot.decode.commands, 3);
    assert_eq!(snapshot.good.characters.len(), 1);
    assert_eq!(snapshot.good.characters[0].level, 90);
    assert_eq!(snapshot.good.artifacts.len(), 1);
    assert_eq!(snapshot.good.weapons.len(), 1);
    assert_eq!(snapshot.good.materials["Mora"], 123_456);

    // Snapshotting is non-consuming, so another update still sees the data.
    let later = pcap2good_core::snapshot_outcome(decoder.snapshot());
    assert_eq!(later.good.characters.len(), 1);
    assert_eq!(later.capture.packets, frames.len() as u64);

    // The decoder can still be finished normally after taking snapshots.
    let finished = decoder.finish(Default::default());
    assert_eq!(finished.decode.commands, 3);
    assert_eq!(finished.capture.packets, frames.len() as u64);
    assert_eq!(finished.flows[0].good.characters.len(), 1);
}

#[test]
fn compact_output_is_a_single_line() {
    let path = temp_capture("materials", &capture_with_game_data());
    let output = run_cli(&path, &["--compact"]);
    fs::remove_file(&path).ok();

    assert!(
        output.status.success(),
        "decode failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    // Compact output must still be a single line.
    assert_eq!(
        String::from_utf8_lossy(&output.stdout)
            .trim_end()
            .lines()
            .count(),
        1
    );
}

#[test]
fn writes_good_data_to_output_file() {
    let frames = vec![ethernet_frame(&udp_packet(&[0, 0, 0, 0xff]))];
    let capture = temp_capture("output-file", &frames);
    let out =
        std::env::temp_dir().join(format!("pcap2good-it-{}-good.json", std::process::id()));
    fs::remove_file(&out).ok();

    let output = run_cli(&capture, &["--out", out.to_str().unwrap()]);
    fs::remove_file(&capture).ok();

    assert!(
        output.status.success(),
        "decode failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        output.stdout.is_empty(),
        "stdout should be empty when --out is used: {}",
        String::from_utf8_lossy(&output.stdout)
    );

    let contents = fs::read_to_string(&out).expect("output file was not written");
    let good: serde_json::Value =
        serde_json::from_str(&contents).expect("output file is not valid JSON");
    assert_eq!(good["format"], "GOOD");
    assert_eq!(good["version"], 3);
    assert!(
        contents.ends_with('\n'),
        "output file must end with a newline"
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("Exported 0 characters"), "{stderr}");

    fs::remove_file(&out).ok();
}

#[test]
fn dumps_commands_as_bin_and_json() {
    let path = temp_capture("dump", &capture_with_game_data());
    let dump_dir =
        std::env::temp_dir().join(format!("pcap2good-it-{}-dump", std::process::id()));
    fs::remove_dir_all(&dump_dir).ok();

    let output = run_cli(&path, &["--dump-commands", dump_dir.to_str().unwrap()]);
    fs::remove_file(&path).ok();

    assert!(
        output.status.success(),
        "decode failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let bin_path = dump_dir.join(format!("0001-{AVATAR_DATA_NOTIFY}.bin"));
    let json_path = dump_dir.join(format!("0001-{AVATAR_DATA_NOTIFY}.json"));
    assert!(bin_path.is_file(), "missing {}", bin_path.display());
    assert!(json_path.is_file(), "missing {}", json_path.display());

    let decoded: serde_json::Value = serde_json::from_slice(&fs::read(&json_path).unwrap())
        .unwrap_or_else(|e| panic!("dump is not valid JSON: {e}"));

    // Commands built by the tests carry an empty PacketHead.
    assert_eq!(decoded["header"], serde_json::json!({}));

    // AvatarDataNotify.avatar_list is field 6 and holds one AvatarInfo.
    let avatar = &decoded["body"]["6"];
    assert!(avatar.is_object(), "avatar is not an object: {avatar:?}");
    assert!(
        avatar
            .as_object()
            .unwrap()
            .keys()
            .all(|key| key.parse::<u32>().is_ok()),
        "keys are not field numbers: {avatar:?}"
    );

    // Every command gets a JSON file, not just the first one.
    assert!(
        dump_dir
            .join(format!("0002-{PLAYER_STORE_NOTIFY}.json"))
            .is_file()
    );

    fs::remove_dir_all(&dump_dir).ok();
}

#[test]
fn capture_without_game_data_produces_empty_export() {
    // A handshake followed by a KCP segment that cannot be decrypted, which
    // makes the game sniffer log an internal error that must not reach the
    // user by default.
    let frames = vec![
        ethernet_frame(&udp_packet(&[0, 0, 0, 0xff])),
        ethernet_frame(&udp_packet(&kcp_segment(0, &[0x42; 64]))),
    ];
    let path = temp_capture("empty", &frames);
    let output = run_cli(&path, &[]);
    fs::remove_file(&path).ok();

    assert!(output.status.success());

    let good: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(good["characters"].as_array().unwrap().len(), 0);
    assert_eq!(good["artifacts"].as_array().unwrap().len(), 0);
    assert_eq!(good["weapons"].as_array().unwrap().len(), 0);

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("no character or inventory data"),
        "{stderr}"
    );
    assert!(!stderr.contains("No dispatch key"), "{stderr}");
}

#[test]
fn many_undecryptable_packets_report_the_session_key_problem() {
    // Captures of game versions whose login exchange cannot be decoded look
    // like this: a handshake and lots of traffic, almost none of it decryptable.
    let mut frames = vec![ethernet_frame(&udp_packet(&[0, 0, 0, 0xff]))];
    for sequence in 0..25u32 {
        frames.push(ethernet_frame(&udp_packet(&kcp_segment(
            sequence,
            &[0x42; 64],
        ))));
    }

    let path = temp_capture("undecryptable", &frames);
    let output = run_cli(&path, &[]);
    fs::remove_file(&path).ok();

    assert!(output.status.success());

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("session key was not established"),
        "{stderr}"
    );
}

#[test]
fn compressed_login_response_is_reported() {
    // PacketHead carrying field 8 = 25576, the decompressed size, while the
    // body is only 20071 bytes long.
    let header = [0x18, 0x01, 0x30, 0x2a, 0x40, 0xe8, 0xc7, 0x01];
    let body = [0x42; 20071];
    let command = game_command_with_header(3713, &header, &body);

    let mut frames = vec![ethernet_frame(&udp_packet(&[0, 0, 0, 0xff]))];
    frames.push(ethernet_frame(&udp_packet(&kcp_segment(0, &command))));

    let path = temp_capture("compressed", &frames);
    let output = run_cli(&path, &[]);
    fs::remove_file(&path).ok();

    assert!(output.status.success());

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("compressed its login response"), "{stderr}");
    assert!(stderr.contains("re-capture"), "{stderr}");
}

#[test]
fn failing_to_open_the_capture_is_an_error() {
    let path = Path::new("this-capture-does-not-exist.pcap");
    let output = run_cli(path, &[]);

    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("Failed to open capture file"), "{stderr}");
}

#[test]
fn ethernet_header_is_the_expected_length() {
    // Guards against accidentally stripping the wrong number of bytes when
    // wrapping frames.
    assert_eq!(ethernet_frame(&[]).len(), ETHERNET_HEADER_LEN);
}

#[test]
fn empty_file_is_an_error() {
    let path =
        std::env::temp_dir().join(format!("pcap2good-it-{}-zero.pcap", std::process::id()));
    fs::write(&path, b"").unwrap();
    let output = run_cli(&path, &[]);
    fs::remove_file(&path).ok();

    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("is empty"), "{stderr}");
}

#[test]
fn avatar_data_is_detected_by_content_not_command_id() {
    let body = avatar_list_with_field(42, &[character_avatar(CHARACTER_ID, 100, 90)]);
    let frames = vec![
        handshake_frame(40000),
        ethernet_frame(&udp_packet_for_client(
            40000,
            &kcp_segment(0, &game_command(4242, body)),
        )),
    ];

    let outcome =
        pcap2good_core::decode_capture_bytes(&pcap_bytes(&frames), &Default::default(), None)
            .unwrap();

    assert_eq!(outcome.good.characters.len(), 1);
    assert_eq!(outcome.good.characters[0].level, 90);
    assert_eq!(outcome.flows[0].stats.avatar_packets, 1);
}

#[test]
fn avatar_field_with_an_out_of_range_id_is_not_used() {
    let body = avatar_list_with_field(
        42,
        &[
            character_avatar(CHARACTER_ID, 100, 90),
            character_avatar(12_345, 101, 80),
        ],
    );
    let frames = vec![
        handshake_frame(40000),
        ethernet_frame(&udp_packet_for_client(
            40000,
            &kcp_segment(0, &game_command(4242, body)),
        )),
    ];

    let outcome =
        pcap2good_core::decode_capture_bytes(&pcap_bytes(&frames), &Default::default(), None)
            .unwrap();

    assert!(outcome.good.characters.is_empty());
    assert_eq!(outcome.flows[0].stats.avatar_packets, 0);
}

#[test]
fn character_items_are_not_mistaken_for_avatar_lists() {
    let item = Item {
        // Character items share the player avatar id range.
        item_id: CHARACTER_ID,
        guid: 100,
        detail: Some(item::Detail::Material(Material {
            count: 1,
            ..Default::default()
        })),
        ..Default::default()
    };
    let body = message_list_with_field(42, &[item]);
    let frames = vec![
        handshake_frame(40000),
        ethernet_frame(&udp_packet_for_client(
            40000,
            &kcp_segment(0, &game_command(4242, body)),
        )),
    ];

    let outcome =
        pcap2good_core::decode_capture_bytes(&pcap_bytes(&frames), &Default::default(), None)
            .unwrap();

    assert!(outcome.good.characters.is_empty());
    assert_eq!(outcome.flows[0].stats.avatar_packets, 0);
}

#[test]
fn item_data_is_detected_by_content_not_command_id() {
    let body = message_list_with_field(42, &inventory_items());
    let frames = vec![handshake_frame(40000), content_frame(4242, body)];

    let outcome =
        pcap2good_core::decode_capture_bytes(&pcap_bytes(&frames), &Default::default(), None)
            .unwrap();

    assert_eq!(outcome.flows[0].stats.item_packets, 1);
    assert!(outcome.good.materials.contains_key("Sunsettia"));
}

#[test]
fn item_list_with_fewer_than_ten_items_is_ignored() {
    let items: Vec<Item> = inventory_items().into_iter().take(9).collect();
    let body = message_list_with_field(42, &items);
    let frames = vec![handshake_frame(40000), content_frame(4242, body)];

    let outcome =
        pcap2good_core::decode_capture_bytes(&pcap_bytes(&frames), &Default::default(), None)
            .unwrap();

    assert_eq!(outcome.flows[0].stats.item_packets, 0);
}

#[test]
fn item_list_with_too_many_unknown_ids_is_ignored() {
    let mut items: Vec<Item> = (0..9).map(|i| material_item(100 + i, 1)).collect();
    // 9/11 known is below 90%.
    items.push(unknown_item(200));
    items.push(unknown_item(201));

    let body = message_list_with_field(42, &items);
    let frames = vec![handshake_frame(40000), content_frame(4242, body)];

    let outcome =
        pcap2good_core::decode_capture_bytes(&pcap_bytes(&frames), &Default::default(), None)
            .unwrap();

    assert_eq!(outcome.flows[0].stats.item_packets, 0);
}

#[test]
fn item_list_at_ninety_percent_known_is_accepted() {
    let mut items: Vec<Item> = (0..9).map(|i| material_item(100 + i, 1)).collect();
    // 9/10 known is exactly 90%.
    items.push(unknown_item(200));

    let body = message_list_with_field(42, &items);
    let frames = vec![handshake_frame(40000), content_frame(4242, body)];

    let outcome =
        pcap2good_core::decode_capture_bytes(&pcap_bytes(&frames), &Default::default(), None)
            .unwrap();

    assert_eq!(outcome.flows[0].stats.item_packets, 1);
    assert!(outcome.good.materials.contains_key("Sunsettia"));
}

#[test]
fn later_item_updates_do_not_replace_the_inventory() {
    let full = message_list_with_field(42, &inventory_items());
    let updates: Vec<Item> = (0..11).map(|i| material_item(500 + i, 1)).collect();
    let update = message_list_with_field(42, &updates);

    let frames = vec![
        handshake_frame(40000),
        ethernet_frame(&udp_packet_for_client(
            40000,
            &kcp_segment(0, &game_command(4242, full)),
        )),
        ethernet_frame(&udp_packet_for_client(
            40000,
            &kcp_segment(1, &game_command(4242, update)),
        )),
    ];

    let outcome =
        pcap2good_core::decode_capture_bytes(&pcap_bytes(&frames), &Default::default(), None)
            .unwrap();

    assert_eq!(outcome.flows[0].stats.item_packets, 2);
    assert_eq!(outcome.good.artifacts.len(), 1);
    assert_eq!(outcome.good.weapons.len(), 1);
    assert!(outcome.good.materials.contains_key("Sunsettia"));
}

fn achievement_frames() -> Vec<Vec<u8>> {
    let entries: Vec<Vec<u8>> = (0..12)
        .map(|index| {
            let status = match index {
                0 => 3,
                1 => 2,
                _ => 1,
            };
            let finish_timestamp = (status >= 2).then_some(1_700_000_000 + index as u32);
            achievement_entry(80001 + index as u32, status, finish_timestamp)
        })
        .collect();
    let body = raw_list_with_field(9, &entries);
    vec![handshake_frame(40000), content_frame(4164, body)]
}

#[test]
fn achievement_packet_is_detected_by_content() {
    let frames = achievement_frames();
    let outcome =
        pcap2good_core::decode_capture_bytes(&pcap_bytes(&frames), &Default::default(), None)
            .unwrap();

    assert_eq!(outcome.achievements.gi_achievements, vec![80001, 80002]);
    assert_eq!(outcome.flows[0].stats.achievement_packets, 1);
    assert_eq!(outcome.flows[0].achievements.achievements.len(), 12);
    assert!(outcome.warnings.is_empty());
}

#[test]
fn achievement_list_with_unknown_ids_is_ignored() {
    let entries: Vec<Vec<u8>> = (0..12)
        .map(|index| achievement_entry(1_000_000 + index, 3, Some(1_700_000_000 + index)))
        .collect();
    let body = raw_list_with_field(9, &entries);
    let frames = vec![handshake_frame(40000), content_frame(4164, body)];

    let outcome =
        pcap2good_core::decode_capture_bytes(&pcap_bytes(&frames), &Default::default(), None)
            .unwrap();

    assert!(outcome.achievements.gi_achievements.is_empty());
    assert_eq!(outcome.flows[0].stats.achievement_packets, 0);
}

#[test]
fn cli_writes_achievements_to_a_separate_file() {
    let capture = temp_capture("achievements", &achievement_frames());
    let out = std::env::temp_dir().join(format!(
        "pcap2good-it-{}-achievements.json",
        std::process::id()
    ));
    fs::remove_file(&out).ok();

    let output = run_cli(&capture, &["--achievements", out.to_str().unwrap()]);
    fs::remove_file(&capture).ok();

    assert!(
        output.status.success(),
        "decode failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let achievements: serde_json::Value = serde_json::from_slice(&fs::read(&out).unwrap())
        .unwrap_or_else(|error| panic!("achievements file is not JSON: {error}"));
    fs::remove_file(&out).ok();
    assert_eq!(
        achievements["gi_achievements"],
        serde_json::json!([80001, 80002])
    );
}

#[test]
fn multiple_flows_are_decoded_independently() {
    let frames = vec![
        handshake_frame(40000),
        handshake_frame(40001),
        avatar_frame(40000, 0, 90),
        avatar_frame(40001, 0, 80),
    ];

    let outcome =
        pcap2good_core::decode_capture_bytes(&pcap_bytes(&frames), &Default::default(), None)
            .unwrap();

    assert_eq!(outcome.flows.len(), 2);
    assert_eq!(outcome.selected_flow, Some(outcome.flows[0].id));
    assert_eq!(outcome.good.characters.len(), 1);
    assert_eq!(outcome.good.characters[0].level, 90);
    assert_eq!(outcome.flows[1].good.characters.len(), 1);
    assert_eq!(outcome.flows[1].good.characters[0].level, 80);
    assert!(outcome.warnings.iter().any(|warning| matches!(
        warning.code,
        pcap2good_core::WarningCode::MultipleFlows { count: 2 }
    )));
}

#[test]
fn reconnecting_on_the_same_flow_key_starts_a_new_session() {
    let frames = vec![
        handshake_frame(40000),
        avatar_frame(40000, 0, 90),
        handshake_frame(40000),
        avatar_frame(40000, 0, 80),
    ];

    let outcome =
        pcap2good_core::decode_capture_bytes(&pcap_bytes(&frames), &Default::default(), None)
            .unwrap();

    assert_eq!(outcome.flows.len(), 2);
    assert_eq!(outcome.flows[0].good.characters[0].level, 90);
    assert_eq!(outcome.flows[1].good.characters[0].level, 80);
    assert_eq!(outcome.good.characters[0].level, 90);
}

#[test]
fn selects_the_first_flow_with_player_data() {
    let frames = vec![
        handshake_frame(40000),
        handshake_frame(40001),
        avatar_frame(40001, 0, 80),
    ];

    let outcome =
        pcap2good_core::decode_capture_bytes(&pcap_bytes(&frames), &Default::default(), None)
            .unwrap();

    assert_eq!(outcome.flows.len(), 2);
    assert_eq!(outcome.selected_flow, Some(outcome.flows[1].id));
    assert_eq!(outcome.good.characters.len(), 1);
    assert_eq!(outcome.good.characters[0].level, 80);
    assert!(!outcome.warnings.iter().any(|warning| matches!(
        warning.code,
        pcap2good_core::WarningCode::MultipleFlows { .. }
    )));
}

#[test]
fn multiple_flows_without_player_data_do_not_warn() {
    let frames = vec![handshake_frame(40000), handshake_frame(40001)];

    let outcome =
        pcap2good_core::decode_capture_bytes(&pcap_bytes(&frames), &Default::default(), None)
            .unwrap();

    assert_eq!(outcome.flows.len(), 2);
    assert!(!outcome.warnings.iter().any(|warning| matches!(
        warning.code,
        pcap2good_core::WarningCode::MultipleFlows { .. }
    )));
}

#[test]
fn handshake_on_one_flow_does_not_reset_another_flow() {
    let frames = vec![
        handshake_frame(40000),
        avatar_frame(40000, 0, 90),
        handshake_frame(40001),
        avatar_frame(40000, 1, 80),
    ];

    let outcome =
        pcap2good_core::decode_capture_bytes(&pcap_bytes(&frames), &Default::default(), None)
            .unwrap();

    assert_eq!(outcome.flows.len(), 2);
    assert_eq!(outcome.flows[0].stats.commands, 2);
    assert_eq!(outcome.flows[0].good.characters[0].level, 80);
    assert_eq!(outcome.flows[1].stats.commands, 0);
}

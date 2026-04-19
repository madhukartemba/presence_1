#include "esphome.h"
#include <algorithm>
#include <cstring>
#include <esp_now.h>
#include <map>
#include <string>
#include <vector>

// ==========================================
// NEW: Cryptography Includes
// ==========================================
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/ecdh.h>
#include <mbedtls/entropy.h>
#include <mbedtls/gcm.h>

// ESP-NOW receive path: encrypted app traffic (AES-GCM) vs cleartext pairing (ECDH only when pairing_mode_active).
// Sender must use identical packed structs and IV rule: sessionId (8 LE) || counter (4 LE) for GCM nonce.
// Hub→clicker ACK (EncryptedAckPacket): same key, IV = sessionId (8 LE) || (~counter) (4 LE) — must not reuse the
// request IV (GCM forbids same nonce for two plaintexts under one key). Plaintext AckMessage: counter, sessionId,
// success, reason (AckReason: ACK_OK, ACK_SESSION_ID_ZERO, ACK_REPLAY_COUNTER, ACK_SESSION_RETIRED on failure).

// ==========================================
// Security & Pairing Globals
// ==========================================
static constexpr size_t SESSION_HISTORY_LEN = 16;

struct DeviceKey {
  uint8_t key[16];
  uint32_t last_counter = 0; // Monotonic within current_session_id; synced over MQTT
  uint64_t current_session_id = 0;
  /// Retired session IDs (FIFO); must not accept replays using these.
  uint64_t session_history[SESSION_HISTORY_LEN] = {};
};

// Key = sender MAC as 12 lowercase hex chars (see mac_to_str). Value synced via retained esp_click/device/<mac>.
std::map<std::string, DeviceKey> known_devices;
/// Set true after first MQTT device update (YAML); avoids LED flash on retained replay at boot.
inline bool mqtt_paired_initial_sync_done = false;
// Set by ESPHome template switch; when false, cleartext pairing frames are dropped.
bool pairing_mode_active = false;

// Pairing success requests YAML to turn off pairing_mode_switch (see interval).
inline volatile bool g_request_close_pairing_mode = false;
/// When true, next pairing switch turn-off skips the red LED (green success just ran).
inline volatile bool g_pairing_close_skip_red_led = false;

// 1. Unified Enums
enum PressEvent { NONE_PRESS, SINGLE_PRESS, DOUBLE_PRESS, LONG_PRESS };
enum BatteryStatus {
  CHARGING,
  DISCHARGING,
  FULL_CHARGED,
  NOT_CONNECTED,
  CHARGE_FAULT
};

// 2. Packed Structs
enum MessageType {
  BUTTON_PRESS,
  BATTERY_STATUS,
  DISCOVERY_REQUEST,
  PAIRING_REQUEST,
  PAIRING_RESPONSE,
  UNPAIR_REQUEST,
};

enum AckReason : uint8_t {
  ACK_OK = 0,
  ACK_SESSION_ID_ZERO = 1,
  ACK_REPLAY_COUNTER = 2,
  ACK_SESSION_RETIRED = 3,
};

// App-level ACK plaintext (encrypted on wire as EncryptedAckPacket for paired devices).
struct __attribute__((packed)) AckMessage {
  uint32_t counter;
  uint64_t sessionId = 0;
  bool success;
  AckReason reason = ACK_OK;
};

// Cleartext Message structure
struct __attribute__((packed)) Message {
  uint32_t counter;
  uint64_t sessionId = 0; // 0 = pairing / plaintext; must match GCM IV when encrypted
  int deviceId = 0;
  MessageType type;
  union {
    struct {
      int buttonId;
      PressEvent event;
    } buttonPress;

    struct {
      int level;
      BatteryStatus status;
    } batteryLevel;

    struct {
      size_t keyLen;
      uint8_t publicKey[65];
    } pairing;
  } data;
};

#define AES_IV_LENGTH 12
#define AES_TAG_LENGTH 16

// Wire format for post-pairing traffic; sizeof() distinguishes from cleartext Message in handle_espnow_packet.
struct __attribute__((packed)) EncryptedPacket {
  uint8_t iv[AES_IV_LENGTH];
  uint8_t ciphertext[sizeof(Message)];
  uint8_t tag[AES_TAG_LENGTH];
};

// AES-GCM wire format for hub→paired-device ACK (sizeof distinguishes from EncryptedPacket / Message).
struct __attribute__((packed)) EncryptedAckPacket {
  uint8_t iv[AES_IV_LENGTH];
  uint8_t ciphertext[sizeof(AckMessage)];
  uint8_t tag[AES_TAG_LENGTH];
};

// GCM IV for hub→device ACK (differs from request IV which uses raw counter in last 4 bytes).
static inline void build_ack_iv(uint64_t session_id, uint32_t counter,
                                uint8_t iv[AES_IV_LENGTH]) {
  memcpy(iv, &session_id, sizeof(session_id));
  uint32_t ctr_flipped = ~counter;
  memcpy(iv + sizeof(session_id), &ctr_flipped, sizeof(ctr_flipped));
}

// Trackers
std::vector<std::string> discovered_macs;
std::vector<std::string> discovered_buttons;

// Helper: MAC to String
std::string mac_to_str(const uint8_t *mac) {
  char buf[13];
  snprintf(buf, sizeof(buf), "%02x%02x%02x%02x%02x%02x", mac[0], mac[1], mac[2],
           mac[3], mac[4], mac[5]);
  return std::string(buf);
}

// Helper: Hex Array to String (for MQTT syncing)
std::string hex_encode(const uint8_t *data, size_t len) {
  char buf[len * 2 + 1];
  for (size_t i = 0; i < len; ++i)
    snprintf(buf + i * 2, 3, "%02x", data[i]);
  return std::string(buf);
}

std::string hex_encode_u64(uint64_t v) {
  uint8_t b[8];
  memcpy(b, &v, sizeof(v));
  return hex_encode(b, sizeof(b));
}

bool hex_decode_u64(const std::string &s, uint64_t *out) {
  if (s.length() != 16 || out == nullptr)
    return false;
  uint8_t b[8];
  for (int i = 0; i < 8; i++) {
    std::string byteString = s.substr(i * 2, 2);
    char *end = nullptr;
    unsigned long byte_val = strtoul(byteString.c_str(), &end, 16);
    if (end != byteString.c_str() + 2 || byte_val > 255)
      return false;
    b[i] = (uint8_t)byte_val;
  }
  memcpy(out, b, sizeof(uint64_t));
  return true;
}

// After decrypt: wire IV must equal sessionId||counter from plaintext (same rule the clicker uses to encrypt).
static bool iv_matches_plaintext(const EncryptedPacket *ep, const Message *msg) {
  uint8_t expected[AES_IV_LENGTH];
  memcpy(expected, &msg->sessionId, sizeof(msg->sessionId));
  memcpy(expected + sizeof(msg->sessionId), &msg->counter, sizeof(msg->counter));
  return memcmp(expected, ep->iv, AES_IV_LENGTH) == 0;
}

// Retired session IDs still reject replays after the clicker rotates rtcSessionId (FIFO).
static bool session_id_is_retired(const DeviceKey &dk, uint64_t sid) {
  for (size_t i = 0; i < SESSION_HISTORY_LEN; i++) {
    if (dk.session_history[i] == sid)
      return true;
  }
  return false;
}

static void retire_current_session(DeviceKey &dk) {
  if (dk.current_session_id == 0)
    return;
  memmove(dk.session_history + 1, dk.session_history,
           (SESSION_HISTORY_LEN - 1) * sizeof(uint64_t));
  dk.session_history[0] = dk.current_session_id;
  dk.current_session_id = 0;
}

// Updates last_counter and session tracking. New sessionId rotates current into history (see retire_current_session).
// Returns ACK_OK on success; otherwise a reason for encrypted failure ACK to the sender.
static AckReason accept_session_and_counter(DeviceKey &dk, uint64_t session_id,
                                            uint32_t counter) {
  if (session_id == 0) {
    ESP_LOGW("esp_click", "Rejecting encrypted packet: sessionId 0 invalid");
    return ACK_SESSION_ID_ZERO;
  }

  if (dk.current_session_id == session_id) {
    if (counter <= dk.last_counter) {
      ESP_LOGW("esp_click",
               "Replay attack (counter) from session 0x%016llx. Dropped.",
               (unsigned long long)session_id);
      return ACK_REPLAY_COUNTER;
    }
    dk.last_counter = counter;
    return ACK_OK;
  }

  if (session_id_is_retired(dk, session_id)) {
    ESP_LOGW("esp_click",
             "Replay attack (retired session) 0x%016llx. Dropped.",
             (unsigned long long)session_id);
    return ACK_SESSION_RETIRED;
  }

  retire_current_session(dk);
  dk.current_session_id = session_id;
  dk.last_counter = counter;
  return ACK_OK;
}

// Publishes retained homeassistant/.../config topics once per (mac) and per (mac, entity_id); tracks discovered_* to dedupe.
void publish_mqtt_discovery(const std::string &mac, int entity_id) {
  if (mqtt::global_mqtt_client == nullptr ||
      !mqtt::global_mqtt_client->is_connected())
    return;

  std::string device_json = R"("device":{"identifiers":["esp_click_)" + mac +
                            R"("],"name":"ESP Click )" + mac +
                            R"(","manufacturer":"ESP Click Project"})";

  if (std::find(discovered_macs.begin(), discovered_macs.end(), mac) ==
      discovered_macs.end()) {
    ESP_LOGI("esp_click", "Publishing HA Discovery for Device Battery: %s",
             mac.c_str());
    std::string bat_topic =
        "homeassistant/sensor/esp_click_" + mac + "/batt/config";
    std::string bat_payload =
        R"({"name":"Battery Level","state_topic":"esp_click/)" + mac +
        R"(/battery_level","unit_of_measurement":"%","device_class":"battery","unique_id":"esp_click_)" +
        mac + R"(_bat",)" + device_json + R"(})";
    mqtt::global_mqtt_client->publish(bat_topic, bat_payload, 0, true);

    std::string stat_topic =
        "homeassistant/sensor/esp_click_" + mac + "/stat/config";
    std::string stat_payload =
        R"({"name":"Battery Status","state_topic":"esp_click/)" + mac +
        R"(/battery_status","icon":"mdi:battery-charging","unique_id":"esp_click_)" +
        mac + R"(_stat",)" + device_json + R"(})";
    mqtt::global_mqtt_client->publish(stat_topic, stat_payload, 0, true);

    discovered_macs.push_back(mac);
  }

  std::string button_key = mac + "_" + std::to_string(entity_id);
  if (std::find(discovered_buttons.begin(), discovered_buttons.end(),
                button_key) == discovered_buttons.end()) {
    ESP_LOGI("esp_click",
             "Publishing HA Discovery for Device Triggers: %s (Entity %d)",
             mac.c_str(), entity_id);
    std::string base_state_topic =
        "esp_click/" + mac + "/entity_" + std::to_string(entity_id) + "/event";
    std::string ha_subtype = "button_" + std::to_string(entity_id + 1);

    std::string single_topic = "homeassistant/device_automation/esp_click_" +
                               mac + "/btn_" + std::to_string(entity_id) +
                               "_single/config";
    std::string single_payload =
        R"({"automation_type":"trigger","type":"button_short_press","subtype":")" +
        ha_subtype + R"(","payload":"single","topic":")" + base_state_topic +
        R"(",)" + device_json + R"(})";
    mqtt::global_mqtt_client->publish(single_topic, single_payload, 0, true);

    std::string double_topic = "homeassistant/device_automation/esp_click_" +
                               mac + "/btn_" + std::to_string(entity_id) +
                               "_double/config";
    std::string double_payload =
        R"({"automation_type":"trigger","type":"button_double_press","subtype":")" +
        ha_subtype + R"(","payload":"double","topic":")" + base_state_topic +
        R"(",)" + device_json + R"(})";
    mqtt::global_mqtt_client->publish(double_topic, double_payload, 0, true);

    std::string long_topic = "homeassistant/device_automation/esp_click_" +
                             mac + "/btn_" + std::to_string(entity_id) +
                             "_long/config";
    std::string long_payload =
        R"({"automation_type":"trigger","type":"button_long_press","subtype":")" +
        ha_subtype + R"(","payload":"long","topic":")" + base_state_topic +
        R"(",)" + device_json + R"(})";
    mqtt::global_mqtt_client->publish(long_topic, long_payload, 0, true);

    discovered_buttons.push_back(button_key);
  }
}

static constexpr const char MQTT_DEVICE_TOPIC_PREFIX[] = "esp_click/device/";

static std::string mqtt_device_topic(const std::string &mac) {
  return std::string(MQTT_DEVICE_TOPIC_PREFIX) + mac;
}

// Drops one MAC from known_devices, clears retained esp_click/device/<mac>, trims HA discovery caches.
static void remove_paired_device_from_hub(const std::string &mac) {
  mqtt_ensure_device_sync_subscription();
  int old_size = (int)known_devices.size();
  if (known_devices.erase(mac) == 0)
    return;

  discovered_macs.erase(std::remove(discovered_macs.begin(), discovered_macs.end(), mac),
                        discovered_macs.end());
  const std::string btn_prefix = mac + "_";
  discovered_buttons.erase(
      std::remove_if(discovered_buttons.begin(), discovered_buttons.end(),
                     [&](const std::string &k) {
                       return k.size() >= btn_prefix.size() &&
                              k.compare(0, btn_prefix.size(), btn_prefix) == 0;
                     }),
      discovered_buttons.end());

  if (mqtt::global_mqtt_client != nullptr &&
      mqtt::global_mqtt_client->is_connected())
    mqtt::global_mqtt_client->publish(mqtt_device_topic(mac), std::string(), 0,
                                      true);

  ESP_LOGI("esp_click", "Removed paired device %s (UNPAIR_REQUEST)", mac.c_str());

  if (mqtt_paired_initial_sync_done && old_size > 0 && known_devices.empty()) {
    static const LedColor red = {255, 0, 0};
    led_play_reverse_center_wave(&red, 1);
  }
  mqtt_paired_initial_sync_done = true;
}

// Subscribed in C++ so we get (topic, payload); YAML on_message only exposes payload as x.
static void mqtt_on_device_topic(const std::string &topic, const std::string &payload) {
  const size_t plen = strlen(MQTT_DEVICE_TOPIC_PREFIX);
  if (topic.size() <= plen || topic.compare(0, plen, MQTT_DEVICE_TOPIC_PREFIX) != 0)
    return;
  std::string topic_mac = topic.substr(plen);

  int old_size = (int)known_devices.size();

  if (payload.empty()) {
    if (known_devices.erase(topic_mac) > 0) {
      ESP_LOGI("esp_click", "Removed device %s (MQTT retained delete)",
               topic_mac.c_str());
      if (mqtt_paired_initial_sync_done && old_size > 0 && known_devices.empty()) {
        static const LedColor red = {255, 0, 0};
        led_play_reverse_center_wave(&red, 1);
      }
    }
    mqtt_paired_initial_sync_done = true;
    return;
  }

  JsonDocument doc;
  DeserializationError err = deserializeJson(doc, payload);
  if (err)
    return;
  JsonObjectConst dev = doc.as<JsonObjectConst>();
  std::string mac = dev["mac"].as<std::string>();
  if (mac.empty())
    mac = topic_mac;
  std::string key_hex = dev["key"].as<std::string>();

  DeviceKey dk;
  dk.last_counter = 0;
  dk.current_session_id = 0;
  for (size_t hi = 0; hi < SESSION_HISTORY_LEN; hi++)
    dk.session_history[hi] = 0;

  if (key_hex.length() == 32) {
    for (int i = 0; i < 16; i++) {
      std::string byteString = key_hex.substr(i * 2, 2);
      dk.key[i] = (uint8_t)strtol(byteString.c_str(), NULL, 16);
    }
    if (dev.containsKey("last_counter"))
      dk.last_counter = dev["last_counter"].as<uint32_t>();
    if (dev.containsKey("current_session_id")) {
      std::string sid = dev["current_session_id"].as<std::string>();
      hex_decode_u64(sid, &dk.current_session_id);
    }
    if (dev.containsKey("session_history")) {
      JsonArrayConst hist = dev["session_history"].as<JsonArrayConst>();
      int idx = 0;
      for (JsonVariantConst hv : hist) {
        if (idx >= (int)SESSION_HISTORY_LEN)
          break;
        std::string hs = hv.as<std::string>();
        hex_decode_u64(hs, &dk.session_history[idx]);
        idx++;
      }
    }
    known_devices[mac] = dk;
  }

  int new_size = (int)known_devices.size();
  ESP_LOGI("esp_click", "Merged device %s from MQTT. Total paired: %d", mac.c_str(),
           new_size);

  if (mqtt_paired_initial_sync_done) {
    if (new_size > old_size) {
      static const LedColor green = {0, 255, 0};
      led_play_reverse_center_wave(&green, 1);
    }
  }
  mqtt_paired_initial_sync_done = true;
}

inline void mqtt_ensure_device_sync_subscription() {
  static bool registered = false;
  if (registered || mqtt::global_mqtt_client == nullptr)
    return;
  registered = true;
  mqtt::global_mqtt_client->subscribe(
      "esp_click/device/+",
      [](const std::string &topic, const std::string &payload) {
        mqtt_on_device_topic(topic, payload);
      },
      0);
}

// Retained JSON for one MAC (anti-replay state sync for other nodes / HA).
static void publish_device_key_json_to_mqtt_(const std::string &mac,
                                             const DeviceKey &dk) {
  JsonDocument doc;
  JsonObject dev = doc.to<JsonObject>();
  dev["mac"] = mac;
  dev["key"] = hex_encode(dk.key, 16);
  dev["last_counter"] = dk.last_counter;
  dev["current_session_id"] = hex_encode_u64(dk.current_session_id);
  JsonArray hist = dev["session_history"].to<JsonArray>();
  for (size_t i = 0; i < SESSION_HISTORY_LEN; i++)
    hist.add(hex_encode_u64(dk.session_history[i]));

  std::string json_str;
  serializeJson(doc, json_str);
  mqtt::global_mqtt_client->publish(mqtt_device_topic(mac), json_str, 0, true);
}

/// Publish only this MAC (e.g. after counter/session update on an encrypted packet).
void publish_one_device_to_mqtt(const std::string &mac) {
  mqtt_ensure_device_sync_subscription();
  if (mqtt::global_mqtt_client == nullptr ||
      !mqtt::global_mqtt_client->is_connected())
    return;
  auto it = known_devices.find(mac);
  if (it == known_devices.end())
    return;
  publish_device_key_json_to_mqtt_(mac, it->second);
}

/// Full retained refresh (e.g. after new pairing).
void publish_known_devices_to_mqtt() {
  mqtt_ensure_device_sync_subscription();
  if (mqtt::global_mqtt_client == nullptr ||
      !mqtt::global_mqtt_client->is_connected())
    return;

  for (const auto &pair : known_devices)
    publish_device_key_json_to_mqtt_(pair.first, pair.second);
  ESP_LOGI("esp_click",
           "Published device keys to esp_click/device/<mac> (retained).");
}

// Empty retained payload clears that topic on typical brokers; clears local map.
void clear_all_paired_devices_mqtt() {
  mqtt_ensure_device_sync_subscription();
  if (mqtt::global_mqtt_client == nullptr ||
      !mqtt::global_mqtt_client->is_connected())
    return;

  std::vector<std::string> macs;
  macs.reserve(known_devices.size());
  for (const auto &p : known_devices)
    macs.push_back(p.first);

  for (const auto &mac : macs)
    mqtt::global_mqtt_client->publish(mqtt_device_topic(mac), std::string(), 0,
                                      true);

  known_devices.clear();
  if (!macs.empty()) {
    mqtt_paired_initial_sync_done = true;
    static const LedColor red = {255, 0, 0};
    led_play_reverse_center_wave(&red, 1);
  }
  ESP_LOGI("esp_click", "Cleared all paired devices (per-MQTT-topic delete).");
}

// ==========================================
// AES-GCM Decryption Helper
// ==========================================
// out_msg size is fixed (packed Message); tag authenticates ciphertext + IV.
bool decrypt_packet(const EncryptedPacket *encrypted_packet,
                    const uint8_t *shared_key, Message *out_msg) {
  mbedtls_gcm_context gcm;
  mbedtls_gcm_init(&gcm);

  int ret = mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, shared_key, 128);
  if (ret != 0) {
    ESP_LOGE("esp_click", "Failed to set AES key");
    mbedtls_gcm_free(&gcm);
    return false;
  }

  ret = mbedtls_gcm_auth_decrypt(&gcm, sizeof(Message), encrypted_packet->iv,
                                 AES_IV_LENGTH, NULL, 0, encrypted_packet->tag,
                                 AES_TAG_LENGTH, encrypted_packet->ciphertext,
                                 (unsigned char *)out_msg);

  mbedtls_gcm_free(&gcm);

  if (ret == MBEDTLS_ERR_GCM_AUTH_FAILED) {
    ESP_LOGW("esp_click",
             "AES-GCM Authentication Failed! Tampered packet or wrong key.");
    return false;
  } else if (ret != 0) {
    ESP_LOGE("esp_click", "Decryption error: -0x%04X", -ret);
    return false;
  }

  return true;
}

// ==========================================
// AES-GCM encrypt (hub → paired device ACK)
// ==========================================
static bool encrypt_ack_packet(const AckMessage *plain, const uint8_t *shared_key,
                               uint64_t session_id, uint32_t counter,
                               EncryptedAckPacket *out) {
  uint8_t iv[AES_IV_LENGTH];
  build_ack_iv(session_id, counter, iv);
  memcpy(out->iv, iv, AES_IV_LENGTH);

  mbedtls_gcm_context gcm;
  mbedtls_gcm_init(&gcm);
  if (mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, shared_key, 128) != 0) {
    ESP_LOGE("esp_click", "encrypt_ack: setkey failed");
    mbedtls_gcm_free(&gcm);
    return false;
  }

  int ret = mbedtls_gcm_crypt_and_tag(
      &gcm, MBEDTLS_GCM_ENCRYPT, sizeof(AckMessage), iv, AES_IV_LENGTH, NULL, 0,
      (const unsigned char *)plain, out->ciphertext, AES_TAG_LENGTH, out->tag);

  mbedtls_gcm_free(&gcm);

  if (ret != 0) {
    ESP_LOGE("esp_click", "encrypt_ack: gcm_crypt_and_tag failed: -0x%04X", -ret);
    return false;
  }
  return true;
}

static void send_encrypted_ack_to_peer(const uint8_t *addr,
                                       const std::string &sender_mac,
                                       uint64_t session_id, uint32_t counter,
                                       bool success,
                                       AckReason fail_reason = ACK_OK) {
  auto it = known_devices.find(sender_mac);
  if (it == known_devices.end())
    return;
  AckMessage ack;
  ack.counter = counter;
  ack.sessionId = session_id;
  ack.success = success;
  ack.reason = success ? ACK_OK : fail_reason;
  EncryptedAckPacket pkt;
  if (!encrypt_ack_packet(&ack, it->second.key, session_id, counter, &pkt)) {
    ESP_LOGW("esp_click", "encrypt_ack_packet failed for %s", sender_mac.c_str());
    return;
  }
  esp_err_t err = esp_now_send(addr, (uint8_t *)&pkt, sizeof(pkt));
  if (err != ESP_OK)
    ESP_LOGW("esp_click", "esp_now_send encrypted ACK failed: %s", esp_err_to_name(err));
}

// ==========================================
// Main ESP-NOW Handler
// ==========================================
void handle_espnow_packet(const uint8_t *addr, const uint8_t *data, int size) {
  // Packet type is inferred from size: EncryptedPacket vs cleartext Message (pairing only).

  std::string sender_mac = mac_to_str(addr);
  bool is_known = (known_devices.find(sender_mac) != known_devices.end());

  // ---------------------------------------------------------
  // PATH A: AES-GCM EncryptedPacket (known MAC only)
  // ---------------------------------------------------------
  if (size == sizeof(EncryptedPacket)) {
    if (!is_known) {
      ESP_LOGW("esp_click", "Rejected encrypted packet from unknown MAC: %s",
               sender_mac.c_str());
      return;
    }

    auto encrypted_msg = (const EncryptedPacket *)data;
    Message msg;

    if (!decrypt_packet(encrypted_msg, known_devices[sender_mac].key, &msg)) {
      ESP_LOGE("esp_click", "Decryption failed for %s", sender_mac.c_str());
      return; // Decryption failed, drop packet.
    }

    // Ensures nonce/ciphertext binding: IV cannot be swapped from another packet.
    if (!iv_matches_plaintext(encrypted_msg, &msg)) {
      ESP_LOGW("esp_click",
               "IV / plaintext mismatch for %s (session/counter vs wire IV).",
               sender_mac.c_str());
      return;
    }

    AckReason session_result =
        accept_session_and_counter(known_devices[sender_mac], msg.sessionId,
                                   msg.counter);
    if (session_result != ACK_OK) {
      send_encrypted_ack_to_peer(addr, sender_mac, msg.sessionId, msg.counter,
                                 false, session_result);
      return;
    }

    // Discovery: ACK only; no publish_known_devices_to_mqtt (avoids retained churn; state still updated above).
    if (msg.type == DISCOVERY_REQUEST) {
      ESP_LOGD("esp_click",
               "Received ENCRYPTED Discovery Ping from %s. Sending silent ACK.",
               sender_mac.c_str());
      send_encrypted_ack_to_peer(addr, sender_mac, msg.sessionId, msg.counter,
                                 true);
      return;
    }

    if (msg.type == UNPAIR_REQUEST) {
      ESP_LOGI("esp_click", "UNPAIR_REQUEST from %s — ACK then remove from MQTT",
               sender_mac.c_str());
      send_encrypted_ack_to_peer(addr, sender_mac, msg.sessionId, msg.counter,
                                 true);
      remove_paired_device_from_hub(sender_mac);
      return;
    }

    // App-level ACK must precede MQTT: JSON publish + HA work can exceed the clicker's waitForAck window.
    send_encrypted_ack_to_peer(addr, sender_mac, msg.sessionId, msg.counter,
                               true);

    // Button/battery only (not discovery): sync anti-replay state for this sender only.
    publish_one_device_to_mqtt(sender_mac);

    // HA state topics + local LED feedback (requires MQTT for publish paths above).
    if (mqtt::global_mqtt_client != nullptr &&
        mqtt::global_mqtt_client->is_connected()) {
      if (msg.type == BUTTON_PRESS) {
        publish_mqtt_discovery(sender_mac, msg.data.buttonPress.buttonId);
        std::string base_topic = "esp_click/" + sender_mac + "/entity_" +
                                 std::to_string(msg.data.buttonPress.buttonId);
        std::string payload;
        switch (msg.data.buttonPress.event) {
        case SINGLE_PRESS:
          payload = "single";
          static const LedColor white = {255, 255, 255};
          led_play_reverse_center_wave(&white, 1);
          break;
        case DOUBLE_PRESS:
          payload = "double";
          static const LedColor yellow = {255, 255, 0};
          led_play_reverse_center_wave(&yellow, 1);
          break;
        case LONG_PRESS:
          payload = "long";
          static const LedColor blue = {0, 0, 255};
          led_play_reverse_center_wave(&blue, 1);
          break;
        default:
          payload = "none";
          break;
        }
        mqtt::global_mqtt_client->publish(base_topic + "/event", payload, 0,
                                          false);
        ESP_LOGI("esp_click", "[%s] Button %d: %s (Encrypted)",
                 sender_mac.c_str(), msg.data.buttonPress.buttonId,
                 payload.c_str());
      } else if (msg.type == BATTERY_STATUS) {
        std::string bat_base_topic = "esp_click/" + sender_mac;
        mqtt::global_mqtt_client->publish(
            bat_base_topic + "/battery_level",
            std::to_string(msg.data.batteryLevel.level), 0, true);
        ESP_LOGI("esp_click", "[%s] Battery: %d%% (Encrypted)",
                 sender_mac.c_str(), msg.data.batteryLevel.level);
      }
    }
  }
  // ---------------------------------------------------------
  // PATH B: Cleartext Message (PAIRING_* only, pairing switch on)
  // ---------------------------------------------------------
  else if (size == sizeof(Message)) {
    // Cleartext Message: only valid for PAIRING_REQUEST while pairing switch is on; sessionId must be 0 from sender.

    // 1. If we aren't pairing, drop all cleartext traffic immediately
    if (!pairing_mode_active) {
      // Using LOGD so it doesn't spam the console if a random device broadcasts
      ESP_LOGD("esp_click", "Cleartext packet dropped. Pairing Mode is OFF.");
      return;
    }

    // 2. Strict Downgrade Protection
    if (is_known) {
      ESP_LOGW("esp_click",
               "Strict Mode: Rejected cleartext packet from known device %s. "
               "Possible downgrade attack.",
               sender_mac.c_str());
      return;
    }

    auto msg = (const Message *)data;

    // ECDH Curve25519; first 16 bytes of shared secret become AES-128 key for subsequent EncryptedPackets.
    if (msg->type == PAIRING_REQUEST) {
      ESP_LOGI("esp_click",
               "Pairing Request received from %s. Processing ECDH...",
               sender_mac.c_str());

      // 1. Initialize mbedTLS 3.x for ECDH
      mbedtls_ecdh_context ecdh;
      mbedtls_ctr_drbg_context ctr_drbg;
      mbedtls_entropy_context entropy;

      mbedtls_ecdh_init(&ecdh);
      mbedtls_ctr_drbg_init(&ctr_drbg);
      mbedtls_entropy_init(&entropy);

      const char *pers = "esp_click_rx_pairing";
      mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                            (const unsigned char *)pers, strlen(pers));

      if (mbedtls_ecdh_setup(&ecdh, MBEDTLS_ECP_DP_CURVE25519) != 0) {
        ESP_LOGE("esp_click", "ECDH Setup Failed");
        return;
      }

      // 2. Read Sender's Public Key
      if (mbedtls_ecdh_read_public(&ecdh, msg->data.pairing.publicKey,
                                   msg->data.pairing.keyLen) != 0) {
        ESP_LOGE("esp_click", "Failed to read sender public key");
        return;
      }

      // 3. Generate Receiver's Key Pair & Response Message
      Message responseMsg;
      responseMsg.type = PAIRING_RESPONSE;
      responseMsg.counter = msg->counter;
      responseMsg.sessionId = 0;

      size_t olen = 0;
      if (mbedtls_ecdh_make_public(&ecdh, &olen,
                                   responseMsg.data.pairing.publicKey, 65,
                                   mbedtls_ctr_drbg_random, &ctr_drbg) != 0) {
        ESP_LOGE("esp_click", "Failed to generate receiver public key");
        return;
      }
      responseMsg.data.pairing.keyLen = olen;

      // 4. Calculate Shared Secret
      uint8_t shared_secret[32];
      size_t secret_len;
      if (mbedtls_ecdh_calc_secret(&ecdh, &secret_len, shared_secret,
                                   sizeof(shared_secret),
                                   mbedtls_ctr_drbg_random, &ctr_drbg) == 0) {

        // Success! Save the 16-byte AES key
        DeviceKey new_dev;
        memcpy(new_dev.key, shared_secret, 16);
        new_dev.last_counter = 0;
        new_dev.current_session_id = 0;
        memset(new_dev.session_history, 0, sizeof(new_dev.session_history));
        known_devices[sender_mac] = new_dev;

        // Send the Public Key response back to the sender
        esp_now_send(addr, (uint8_t *)&responseMsg, sizeof(Message));

        ESP_LOGI("esp_click", "Pairing Successful! Key established for %s",
                 sender_mac.c_str());

        static const LedColor green = {0, 255, 0};
        led_play_reverse_center_wave(&green, 1);

        // Sync the new secure map to HA MQTT
        publish_known_devices_to_mqtt();

        g_pairing_close_skip_red_led = true;
        g_request_close_pairing_mode = true;
      }

      mbedtls_ecdh_free(&ecdh);
      mbedtls_ctr_drbg_free(&ctr_drbg);
      mbedtls_entropy_free(&entropy);
    }
  }
}
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

// ==========================================
// Security & Pairing Globals
// ==========================================
struct DeviceKey {
  uint8_t key[16];
  uint32_t last_counter = 0; // Monotonic within current_session_id; synced over MQTT
  uint64_t current_session_id = 0;
  /// Last four retired session IDs (FIFO); must not accept replays using these.
  uint64_t session_history[4] = {};
};

std::map<std::string, DeviceKey> known_devices;
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
  PAIRING_RESPONSE
};

struct __attribute__((packed)) AckMessage {
  uint32_t counter;
  bool success;
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

// NEW: Encrypted Payload Structure
#define AES_IV_LENGTH 12
#define AES_TAG_LENGTH 16

struct __attribute__((packed)) EncryptedPacket {
  uint8_t iv[AES_IV_LENGTH];
  uint8_t ciphertext[sizeof(Message)];
  uint8_t tag[AES_TAG_LENGTH];
};

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

static bool iv_matches_plaintext(const EncryptedPacket *ep, const Message *msg) {
  uint8_t expected[AES_IV_LENGTH];
  memcpy(expected, &msg->sessionId, sizeof(msg->sessionId));
  memcpy(expected + sizeof(msg->sessionId), &msg->counter, sizeof(msg->counter));
  return memcmp(expected, ep->iv, AES_IV_LENGTH) == 0;
}

static bool session_id_is_retired(const DeviceKey &dk, uint64_t sid) {
  for (int i = 0; i < 4; i++) {
    if (dk.session_history[i] == sid)
      return true;
  }
  return false;
}

static void retire_current_session(DeviceKey &dk) {
  if (dk.current_session_id == 0)
    return;
  memmove(dk.session_history + 1, dk.session_history,
           3 * sizeof(uint64_t));
  dk.session_history[0] = dk.current_session_id;
  dk.current_session_id = 0;
}

// Returns false if replay, stale session, or invalid session id.
static bool accept_session_and_counter(DeviceKey &dk, uint64_t session_id,
                                       uint32_t counter) {
  if (session_id == 0) {
    ESP_LOGW("esp_click", "Rejecting encrypted packet: sessionId 0 invalid");
    return false;
  }

  if (dk.current_session_id == session_id) {
    if (counter <= dk.last_counter) {
      ESP_LOGW("esp_click",
               "Replay attack (counter) from session 0x%016llx. Dropped.",
               (unsigned long long)session_id);
      return false;
    }
    dk.last_counter = counter;
    return true;
  }

  if (session_id_is_retired(dk, session_id)) {
    ESP_LOGW("esp_click",
             "Replay attack (retired session) 0x%016llx. Dropped.",
             (unsigned long long)session_id);
    return false;
  }

  retire_current_session(dk);
  dk.current_session_id = session_id;
  dk.last_counter = counter;
  return true;
}

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

// Sync current known devices to MQTT
void publish_known_devices_to_mqtt() {
  if (mqtt::global_mqtt_client != nullptr &&
      mqtt::global_mqtt_client->is_connected()) {
    JsonDocument doc;
    JsonArray array = doc["allowed_devices"].to<JsonArray>();

    for (const auto &pair : known_devices) {
      JsonObject dev = array.add<JsonObject>();
      dev["mac"] = pair.first;
      dev["key"] = hex_encode(pair.second.key, 16);
      dev["last_counter"] = pair.second.last_counter;
      dev["current_session_id"] = hex_encode_u64(pair.second.current_session_id);
      JsonArray hist = dev["session_history"].to<JsonArray>();
      for (int i = 0; i < 4; i++)
        hist.add(hex_encode_u64(pair.second.session_history[i]));
    }

    std::string json_str;
    serializeJson(doc, json_str);
    mqtt::global_mqtt_client->publish(std::string("esp_click/allowed_devices"),
                                      json_str, 0, true);
    ESP_LOGI("esp_click", "Published updated master device list to broker.");
  }
}

// ==========================================
// AES-GCM Decryption Helper
// ==========================================
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
// Main ESP-NOW Handler
// ==========================================
void handle_espnow_packet(const uint8_t *addr, const uint8_t *data, int size) {

  std::string sender_mac = mac_to_str(addr);
  bool is_known = (known_devices.find(sender_mac) != known_devices.end());

  // ---------------------------------------------------------
  // PATH A: ENCRYPTED DATA PACKETS
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
      return; // Decryption failed, drop packet.
    }

    if (!iv_matches_plaintext(encrypted_msg, &msg)) {
      ESP_LOGW("esp_click",
               "IV / plaintext mismatch for %s (session/counter vs wire IV).",
               sender_mac.c_str());
      return;
    }

    if (!accept_session_and_counter(known_devices[sender_mac], msg.sessionId,
                                    msg.counter)) {
      return;
    }

    if (msg.type == DISCOVERY_REQUEST) {
      ESP_LOGD("esp_click",
               "Received ENCRYPTED Discovery Ping from %s. Sending silent ACK.",
               sender_mac.c_str());
      AckMessage ack_msg;
      ack_msg.counter = msg.counter;
      ack_msg.success = true;
      esp_now_send(addr, (uint8_t *)&ack_msg, sizeof(ack_msg));
      return;
    }

    // ACK before MQTT: broker + JSON can exceed the sender's ACK timeout (~100ms).
    {
      AckMessage ack_msg;
      ack_msg.counter = msg.counter;
      ack_msg.success = true;
      esp_now_send(addr, (uint8_t *)&ack_msg, sizeof(ack_msg));
    }

    publish_known_devices_to_mqtt();

    // Process Decrypted Message
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
          static const LedColor blue = {0, 0, 255};
          led_play_reverse_center_wave(&blue, 1);
          break;
        case DOUBLE_PRESS:
          payload = "double";
          static const LedColor magenta = {255, 0, 255};
          led_play_reverse_center_wave(&magenta, 1);
          break;
        case LONG_PRESS:
          payload = "long";
          static const LedColor cyan = {0, 255, 255};
          led_play_reverse_center_wave(&cyan, 1);
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
  // PATH B: CLEARTEXT PAIRING REQUESTS
  // ---------------------------------------------------------
  else if (size == sizeof(Message)) {

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

    // 3. Process the Pairing Request
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
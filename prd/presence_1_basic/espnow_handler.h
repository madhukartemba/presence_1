#include "esphome.h"
#include <algorithm>
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
  uint32_t last_counter = 0; // Prevent replay attacks
};

std::map<std::string, DeviceKey> known_devices;
bool pairing_mode_active = false;

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

// Helper: Publish MQTT Discovery (Unchanged from your code)
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

    // Replay Attack Protection
    if (msg.counter <= known_devices[sender_mac].last_counter &&
        msg.counter != 0) {
      ESP_LOGW("esp_click", "Replay attack detected from %s. Packet dropped.",
               sender_mac.c_str());
      return;
    }
    known_devices[sender_mac].last_counter = msg.counter;

    // ==========================================
    // NEW: Handle Encrypted Discovery Pings
    // ==========================================
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

    // Send ACK
    AckMessage ack_msg;
    ack_msg.counter = msg.counter;
    ack_msg.success = true;
    esp_now_send(addr, (uint8_t *)&ack_msg, sizeof(ack_msg));
  } else if (size == sizeof(Message)) {
    auto msg = (const Message *)data;

    // ==========================================
    // NEW: Strict Downgrade Protection
    // ==========================================
    if (is_known) {
      ESP_LOGW("esp_click",
               "Strict Mode: Rejected cleartext packet from known device %s. "
               "Possible downgrade attack.",
               sender_mac.c_str());
      return;
    }

    if (msg->type == DISCOVERY_REQUEST) {
      AckMessage ack_msg;
      ack_msg.counter = msg->counter;
      ack_msg.success = true;
      esp_now_send(addr, (uint8_t *)&ack_msg, sizeof(ack_msg));
      return;
    }

    if (msg->type == PAIRING_REQUEST) {
      if (!pairing_mode_active) {
        ESP_LOGW("esp_click",
                 "Rejected Pairing Request from %s. Pairing Mode is OFF.",
                 sender_mac.c_str());
        return;
      }

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

      if (mbedtls_ecdh_setup(&ecdh, MBEDTLS_ECP_DP_SECP256R1) != 0) {
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
        known_devices[sender_mac] = new_dev;

        // Send the Public Key response back to the sender
        esp_now_send(addr, (uint8_t *)&responseMsg, sizeof(Message));

        ESP_LOGI("esp_click", "Pairing Successful! Key established for %s",
                 sender_mac.c_str());

        static const LedColor green = {0, 255, 0};
        led_play_reverse_center_wave(&green, 1);

        // Sync the new secure map to HA MQTT
        publish_known_devices_to_mqtt();
      }

      mbedtls_ecdh_free(&ecdh);
      mbedtls_ctr_drbg_free(&ctr_drbg);
      mbedtls_entropy_free(&entropy);
    }
  }
}
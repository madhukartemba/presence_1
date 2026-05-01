#pragma once

#include "esp_click_bridge.h"

void esp_click_led_reverse_wave(const uint8_t *rgb, int passes);

inline EspClickBridge &esp_click_bridge() {
  static EspClickBridge bridge{EspClickBridge::Config{"esp_click", esp_click_led_reverse_wave}};
  return bridge;
}

#define ESP_CLICK_PAIRING_MODE_MACRO
#define pairing_mode_active (esp_click_bridge().pairing_mode_active)

#include "led_engine.h"

inline void esp_click_led_reverse_wave(const uint8_t *rgb, int passes) {
  LedColor c{rgb[0], rgb[1], rgb[2]};
  led_play_reverse_center_wave(&c, passes);
}

#undef ESP_CLICK_PAIRING_MODE_MACRO

#define mqtt_paired_initial_sync_done (esp_click_bridge().mqtt_paired_initial_sync_done)
#define g_request_close_pairing_mode (esp_click_bridge().g_request_close_pairing_mode)
#define g_pairing_close_skip_red_led (esp_click_bridge().g_pairing_close_skip_red_led)

inline void handle_espnow_packet(const uint8_t *addr, const uint8_t *data, int size) {
  esp_click_bridge().handle_packet(addr, data, size);
}

inline void mqtt_ensure_device_sync_subscription() {
  esp_click_bridge().mqtt_ensure_device_sync_subscription();
}

inline void publish_one_device_to_mqtt(const std::string &mac) {
  esp_click_bridge().publish_one_device_to_mqtt(mac);
}

inline void publish_known_devices_to_mqtt() {
  esp_click_bridge().publish_known_devices_to_mqtt();
}

inline void clear_all_paired_devices_mqtt() {
  esp_click_bridge().clear_all_paired_devices_mqtt();
}

inline bool decrypt_packet(const EncryptedPacket *encrypted_packet, const uint8_t *shared_key,
                           Message *out_msg) {
  return EspClickBridge::decrypt_packet(encrypted_packet, shared_key, out_msg);
}

#define SESSION_HISTORY_LEN ESP_CLICK_SESSION_HISTORY_LEN
#define AES_IV_LENGTH ESP_CLICK_AES_IV_LENGTH
#define AES_TAG_LENGTH ESP_CLICK_AES_TAG_LENGTH

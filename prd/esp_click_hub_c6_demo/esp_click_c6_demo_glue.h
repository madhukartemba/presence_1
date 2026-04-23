#pragma once

// Thin singleton + YAML-friendly names; no LED hardware — optional callback left null.
#include "esp_click_hub.h"

inline EspClickHub &esp_click_hub() {
  static EspClickHub hub{};
  return hub;
}

#define pairing_mode_active (esp_click_hub().pairing_mode_active)
#define mqtt_paired_initial_sync_done (esp_click_hub().mqtt_paired_initial_sync_done)
#define g_request_close_pairing_mode (esp_click_hub().g_request_close_pairing_mode)
#define g_pairing_close_skip_red_led (esp_click_hub().g_pairing_close_skip_red_led)

inline void handle_espnow_packet(const uint8_t *addr, const uint8_t *data, int size) {
  esp_click_hub().handle_packet(addr, data, size);
}

inline void mqtt_ensure_device_sync_subscription() {
  esp_click_hub().mqtt_ensure_device_sync_subscription();
}

inline void publish_one_device_to_mqtt(const std::string &mac) {
  esp_click_hub().publish_one_device_to_mqtt(mac);
}

inline void publish_known_devices_to_mqtt() {
  esp_click_hub().publish_known_devices_to_mqtt();
}

inline void clear_all_paired_devices_mqtt() {
  esp_click_hub().clear_all_paired_devices_mqtt();
}

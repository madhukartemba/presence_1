#pragma once
#include "esp_click_bridge.h"

// Latched LED feedback request from the bridge. The YAML interval polls `pending`
// and dispatches the matching `flash_color` script. We can't call ESPHome's
// `id(...)` from a header (declared later in main.cpp), so we go through this
// small global trampoline.
struct EspClickLedRequest {
  volatile bool pending = false;
  uint8_t r = 0;
  uint8_t g = 0;
  uint8_t b = 0;
  int passes = 0;
};

inline EspClickLedRequest &esp_click_led_request() {
  static EspClickLedRequest req;
  return req;
}

inline void esp_click_led_feedback_cb(const uint8_t *rgb, int passes) {
  auto &req = esp_click_led_request();
  req.r = rgb[0];
  req.g = rgb[1];
  req.b = rgb[2];
  req.passes = passes;
  req.pending = true;
}

inline EspClickBridge &esp_click_bridge() {
  static EspClickBridge bridge{
      EspClickBridge::Config{"esp_click", esp_click_led_feedback_cb}};
  return bridge;
}

#define pairing_mode_active (esp_click_bridge().pairing_mode_active)
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

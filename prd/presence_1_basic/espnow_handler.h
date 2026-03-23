#include "esphome.h"
#include <esp_now.h>
#include <vector>
#include <string>
#include <algorithm>

// 1. Unified Enums
enum MessageType { BUTTON_PRESS, BATTERY_STATUS, DISCOVERY_REQUEST };
enum PressEvent { NONE_PRESS, SINGLE_PRESS, DOUBLE_PRESS, LONG_PRESS };
enum BatteryStatus { CHARGING, DISCHARGING, FULL_CHARGED, NOT_CONNECTED, CHARGE_FAULT };

// 2. Packed Structs
struct __attribute__((packed)) Message {
  uint32_t counter;
  int deviceId;
  MessageType type;
  union {
    struct { int buttonId; PressEvent event; } buttonPress;
    struct { int level; BatteryStatus status; } batteryLevel;
  } data;
};

struct __attribute__((packed)) AckMessage {
  uint32_t counter;
  bool success;
};

// Trackers
std::vector<std::string> discovered_macs;    // Tracks Battery Configs (Device-level)
std::vector<std::string> discovered_buttons; // Tracks Button Configs (Entity-level)

// Helper: MAC to String
std::string mac_to_str(const uint8_t *mac) {
  char buf[13];
  snprintf(buf, sizeof(buf), "%02x%02x%02x%02x%02x%02x", 
           mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
  return std::string(buf);
}

// Helper: Publish MQTT Discovery
void publish_mqtt_discovery(const std::string& mac, int entity_id) {
    #ifdef USE_MQTT
    if (mqtt::global_mqtt_client == nullptr || !mqtt::global_mqtt_client->is_connected()) return;
  
    std::string device_json = R"("device":{"identifiers":["esp_click_)" + mac + R"("],"name":"ESP Click )" + mac + R"(","manufacturer":"ESP Click Project"})";
  
    // 1. DEVICE LEVEL (Battery)
    if (std::find(discovered_macs.begin(), discovered_macs.end(), mac) == discovered_macs.end()) {
      ESP_LOGI("esp_click", "Publishing HA Discovery for Device Battery: %s", mac.c_str());
  
      std::string bat_topic = "homeassistant/sensor/esp_click_" + mac + "/batt/config";
      std::string bat_payload = R"({"name":"Battery Level","state_topic":"esp_click/)" + mac + R"(/battery_level","unit_of_measurement":"%","device_class":"battery","unique_id":"esp_click_)" + mac + R"(_bat",)" + device_json + R"(})";
      mqtt::global_mqtt_client->publish(bat_topic, bat_payload, 0, true);
  
      std::string stat_topic = "homeassistant/sensor/esp_click_" + mac + "/stat/config";
      std::string stat_payload = R"({"name":"Battery Status","state_topic":"esp_click/)" + mac + R"(/battery_status","icon":"mdi:battery-charging","unique_id":"esp_click_)" + mac + R"(_stat",)" + device_json + R"(})";
      mqtt::global_mqtt_client->publish(stat_topic, stat_payload, 0, true);
  
      discovered_macs.push_back(mac);
    }
  
    // 2. ENTITY LEVEL (Buttons)
    std::string button_key = mac + "_" + std::to_string(entity_id);
    if (std::find(discovered_buttons.begin(), discovered_buttons.end(), button_key) == discovered_buttons.end()) {
      ESP_LOGI("esp_click", "Publishing HA Discovery for Device Triggers: %s (Entity %d)", mac.c_str(), entity_id);
  
      std::string base_state_topic = "esp_click/" + mac + "/entity_" + std::to_string(entity_id) + "/event";

      // +1 Math trick for the HA UI Subtype ("First Button", "Second Button")
      std::string ha_subtype = "button_" + std::to_string(entity_id + 1);

      // Trigger 1: Single Press
      std::string single_topic = "homeassistant/device_automation/esp_click_" + mac + "/btn_" + std::to_string(entity_id) + "_single/config";
      std::string single_payload = R"({"automation_type":"trigger","type":"button_short_press","subtype":")" + ha_subtype + R"(","payload":"single","topic":")" + base_state_topic + R"(",)" + device_json + R"(})";
      mqtt::global_mqtt_client->publish(single_topic, single_payload, 0, true);

      // Trigger 2: Double Press
      std::string double_topic = "homeassistant/device_automation/esp_click_" + mac + "/btn_" + std::to_string(entity_id) + "_double/config";
      std::string double_payload = R"({"automation_type":"trigger","type":"button_double_press","subtype":")" + ha_subtype + R"(","payload":"double","topic":")" + base_state_topic + R"(",)" + device_json + R"(})";
      mqtt::global_mqtt_client->publish(double_topic, double_payload, 0, true);

      // Trigger 3: Long Press
      std::string long_topic = "homeassistant/device_automation/esp_click_" + mac + "/btn_" + std::to_string(entity_id) + "_long/config";
      std::string long_payload = R"({"automation_type":"trigger","type":"button_long_press","subtype":")" + ha_subtype + R"(","payload":"long","topic":")" + base_state_topic + R"(",)" + device_json + R"(})";
      mqtt::global_mqtt_client->publish(long_topic, long_payload, 0, true);

      discovered_buttons.push_back(button_key);
    }
    #endif
}


void handle_espnow_packet(const uint8_t *addr, const uint8_t *data, int size) {
    if (size == sizeof(Message)) {
      auto msg = (const Message *)data;
      if (msg->deviceId != 0) return; 
  
      // === NEW: THE PING INTERCEPTOR ===
      if (msg->type == DISCOVERY_REQUEST) {
        ESP_LOGD("esp_click", "Received Discovery Ping from MAC. Sending silent ACK.");
        AckMessage ack_msg;
        ack_msg.counter = msg->counter;
        ack_msg.success = true;
        esp_now_send(addr, (uint8_t *)&ack_msg, sizeof(ack_msg));
        
        // Return immediately! Do not process HA Discovery or MQTT.
        return; 
      }
      // =================================
  
      // If it makes it past the interceptor, it's a real Unicast payload.
      // Proceed with normal HA Discovery and MQTT Publishing...
      
      std::string sender_mac = mac_to_str(addr);
      publish_mqtt_discovery(sender_mac, msg->buttonPress.buttonId);
  
      #ifdef USE_MQTT
      if (mqtt::global_mqtt_client != nullptr && mqtt::global_mqtt_client->is_connected()) {
        // ... (Your existing BUTTON_PRESS and BATTERY_STATUS logic here) ...
      }
      #endif
  
      // Send the ACK for the actual payload
      AckMessage ack_msg;
      ack_msg.counter = msg->counter;
      ack_msg.success = true;
      esp_now_send(addr, (uint8_t *)&ack_msg, sizeof(ack_msg));
    }
  }


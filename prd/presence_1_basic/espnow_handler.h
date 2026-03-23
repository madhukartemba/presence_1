#include "esphome.h"
#include <esp_now.h>
#include <vector>
#include <string>
#include <algorithm>

// 1. Unified Enums
enum MessageType { BUTTON_PRESS, BATTERY_STATUS };
enum PressEvent { NONE_PRESS, SINGLE_PRESS, DOUBLE_PRESS, LONG_PRESS };
enum BatteryStatus { CHARGING, DISCHARGING, FULL_CHARGED, NOT_CONNECTED, CHARGE_FAULT };

// 2. Packed Structs
struct __attribute__((packed)) Message {
  uint32_t counter;
  int deviceId;
  int entityId;
  MessageType type;
  union {
    struct { PressEvent event; } buttonPress;
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
  
    // 1. DEVICE LEVEL (Battery) - Publish only once per MAC address
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
  
    // 2. ENTITY LEVEL (Buttons) - Publish as a SENSOR instead of an EVENT
    std::string button_key = mac + "_" + std::to_string(entity_id);
    if (std::find(discovered_buttons.begin(), discovered_buttons.end(), button_key) == discovered_buttons.end()) {
      ESP_LOGI("esp_click", "Publishing HA Discovery for Button Sensor: %s (Entity %d)", mac.c_str(), entity_id);
  
      // Changed /event/ to /sensor/ in the config topic
      std::string event_topic = "homeassistant/sensor/esp_click_" + mac + "/btn_" + std::to_string(entity_id) + "/config";
      
      // Formatted as a standard sensor with an icon
      std::string event_payload = R"({"name":"Button )" + std::to_string(entity_id) + R"(","state_topic":"esp_click/)" + mac + R"(/entity_)" + std::to_string(entity_id) + R"(/event","icon":"mdi:gesture-tap-button","unique_id":"esp_click_)" + mac + R"(_e)" + std::to_string(entity_id) + R"(_btn",)" + device_json + R"(})";
      
      mqtt::global_mqtt_client->publish(event_topic, event_payload, 0, true);
  
      discovered_buttons.push_back(button_key);
    }
    #endif
}
// 3. The Main Handler Function
void handle_espnow_packet(const uint8_t *addr, const uint8_t *data, int size) {
  if (size == sizeof(Message)) {
    auto msg = (const Message *)data;
    if (msg->deviceId != 0) return; 

    std::string sender_mac = mac_to_str(addr);
    publish_mqtt_discovery(sender_mac, msg->entityId);

    #ifdef USE_MQTT
    if (mqtt::global_mqtt_client != nullptr && mqtt::global_mqtt_client->is_connected()) {
      
      if (msg->type == BUTTON_PRESS) {
        std::string base_topic = "esp_click/" + sender_mac + "/entity_" + std::to_string(msg->entityId);
        std::string payload;
        switch(msg->data.buttonPress.event) {
          case SINGLE_PRESS: payload = "single"; break;
          case DOUBLE_PRESS: payload = "double"; break;
          case LONG_PRESS:   payload = "long";   break;
          default:           payload = "none";   break;
        }
        // Button events are NOT retained
        mqtt::global_mqtt_client->publish(base_topic + "/event", payload, 0, false);
        ESP_LOGI("esp_click", "[%s] Button %d: %s", sender_mac.c_str(), msg->entityId, payload.c_str());
      } 
      
      else if (msg->type == BATTERY_STATUS) {
        // Battery status is published to the MAC level, avoiding entityId
        std::string bat_base_topic = "esp_click/" + sender_mac;
        
        std::string level_payload = std::to_string(msg->data.batteryLevel.level);
        // Retain = TRUE so HA remembers battery between reboots
        mqtt::global_mqtt_client->publish(bat_base_topic + "/battery_level", level_payload, 0, true);

        std::string status_payload;
        switch(msg->data.batteryLevel.status) {
          case CHARGING:      status_payload = "charging"; break;
          case DISCHARGING:   status_payload = "discharging"; break;
          case FULL_CHARGED:  status_payload = "full"; break;
          case NOT_CONNECTED: status_payload = "not_connected"; break;
          case CHARGE_FAULT:  status_payload = "fault"; break;
          default:            status_payload = "unknown"; break;
        }
        // Retain = TRUE
        mqtt::global_mqtt_client->publish(bat_base_topic + "/battery_status", status_payload, 0, true);
        ESP_LOGI("esp_click", "[%s] Battery: %s%% (%s)", sender_mac.c_str(), level_payload.c_str(), status_payload.c_str());
      }
    }
    #endif

    AckMessage ack_msg;
    ack_msg.counter = msg->counter;
    ack_msg.success = true;
    esp_now_send(addr, (uint8_t *)&ack_msg, sizeof(ack_msg));
  }
}
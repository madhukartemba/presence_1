#include "esphome.h"
#include <esp_now.h>
#include <vector>
#include <string>
#include <algorithm>

// ==========================================
// NEW: Security & Pairing Globals
// ==========================================
std::vector<std::string> known_macs;
bool pairing_mode_active = false;

// 1. Unified Enums
enum PressEvent { NONE_PRESS, SINGLE_PRESS, DOUBLE_PRESS, LONG_PRESS };
enum BatteryStatus { CHARGING, DISCHARGING, FULL_CHARGED, NOT_CONNECTED, CHARGE_FAULT };

// 2. Packed Structs
enum MessageType
{
    BUTTON_PRESS,
    BATTERY_STATUS,
    DISCOVERY_REQUEST
};

// Application-level ACK structure MUST be packed
struct __attribute__((packed)) AckMessage
{
    uint32_t counter;
    bool success;
};

// Message structure MUST be packed
struct __attribute__((packed)) Message
{
    uint32_t counter;
    int deviceId = 0;
    MessageType type;
    union
    {
        struct
        {
            int buttonId;
            PressEvent event;
        } buttonPress;

        struct
        {
            int level;
            BatteryStatus status;
        } batteryLevel;
    } data;
};

// Trackers
std::vector<std::string> discovered_macs;    
std::vector<std::string> discovered_buttons; 

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
      std::string ha_subtype = "button_" + std::to_string(entity_id + 1);

      std::string single_topic = "homeassistant/device_automation/esp_click_" + mac + "/btn_" + std::to_string(entity_id) + "_single/config";
      std::string single_payload = R"({"automation_type":"trigger","type":"button_short_press","subtype":")" + ha_subtype + R"(","payload":"single","topic":")" + base_state_topic + R"(",)" + device_json + R"(})";
      mqtt::global_mqtt_client->publish(single_topic, single_payload, 0, true);

      std::string double_topic = "homeassistant/device_automation/esp_click_" + mac + "/btn_" + std::to_string(entity_id) + "_double/config";
      std::string double_payload = R"({"automation_type":"trigger","type":"button_double_press","subtype":")" + ha_subtype + R"(","payload":"double","topic":")" + base_state_topic + R"(",)" + device_json + R"(})";
      mqtt::global_mqtt_client->publish(double_topic, double_payload, 0, true);

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

      std::string sender_mac = mac_to_str(addr);
// ==========================================
      // NEW: SECURITY & AUTHENTICATION INTERCEPTOR
      // ==========================================
      bool is_known = (std::find(known_macs.begin(), known_macs.end(), sender_mac) != known_macs.end());

      if (!is_known) {
          if (pairing_mode_active) {
              ESP_LOGI("esp_click", "Pairing Mode ON. Accepting and pairing new device: %s", sender_mac.c_str());
              known_macs.push_back(sender_mac);
              
              // NO HOME ASSISTANT REQUIRED: ESP builds the JSON and retains it on the broker
              #ifdef USE_MQTT
              if (mqtt::global_mqtt_client != nullptr && mqtt::global_mqtt_client->is_connected()) {
                  // Create a JSON document (ArduinoJson V7)
                  JsonDocument doc;
                  JsonArray array = doc["allowed_macs"].to<JsonArray>();
                  
                  // Add all currently known MACs to the array
                  for (const auto& mac : known_macs) {
                      array.add(mac);
                  }
                  
                  // Serialize to string
                  std::string json_str;
                  serializeJson(doc, json_str);
                  
                  // Publish with retain = true (the 'true' at the end is the magic part)
                  mqtt::global_mqtt_client->publish(std::string("esp_click/allowed_macs"), json_str, 0, true);
                  ESP_LOGI("esp_click", "Published updated master list to broker.");
              }
              #endif
          } else {
              ESP_LOGW("esp_click", "Rejected unknown device: %s. Turn on Pairing Mode to allow.", sender_mac.c_str());
              return; // Drop packet
          }
      }
      // ==========================================

      // THE PING INTERCEPTOR
      if (msg->type == DISCOVERY_REQUEST) {
        ESP_LOGD("esp_click", "Received Discovery Ping from MAC. Sending silent ACK.");
        AckMessage ack_msg;
        ack_msg.counter = msg->counter;
        ack_msg.success = true;
        esp_now_send(addr, (uint8_t *)&ack_msg, sizeof(ack_msg));
        return; 
      }
  
      // Real Unicast payload logic...
      #ifdef USE_MQTT
      if (mqtt::global_mqtt_client != nullptr && mqtt::global_mqtt_client->is_connected()) {
      
      if (msg->type == BUTTON_PRESS) {
          publish_mqtt_discovery(sender_mac, msg->data.buttonPress.buttonId);

          std::string base_topic = "esp_click/" + sender_mac + "/entity_" + std::to_string(msg->data.buttonPress.buttonId);
          std::string payload;
          switch(msg->data.buttonPress.event) {
          case SINGLE_PRESS: {
            payload = "single";
            static const LedColor blue = {0, 0, 255};
            led_play_reverse_center_wave(&blue, 1);
            break;
          }
          case DOUBLE_PRESS: {
            payload = "double";
            static const LedColor magenta = {255, 0, 255};
            led_play_reverse_center_wave(&magenta, 1);
            break;
          }
          case LONG_PRESS: {
            payload = "long";
            static const LedColor cyan = {0, 255, 255};
            led_play_reverse_center_wave(&cyan, 1);
            break;
          }
          default:           payload = "none";   break;
          }
          mqtt::global_mqtt_client->publish(base_topic + "/event", payload, 0, false);
          ESP_LOGI("esp_click", "[%s] Button %d: %s Counter: %d", sender_mac.c_str(), msg->data.buttonPress.buttonId, payload.c_str(), msg->counter);
      } 
      
      else if (msg->type == BATTERY_STATUS) {
          std::string bat_base_topic = "esp_click/" + sender_mac;
          
          std::string level_payload = std::to_string(msg->data.batteryLevel.level);
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
          mqtt::global_mqtt_client->publish(bat_base_topic + "/battery_status", status_payload, 0, true);
          ESP_LOGI("esp_click", "[%s] Battery: %s%% (%s) Counter: %d", sender_mac.c_str(), level_payload.c_str(), status_payload.c_str(), msg->counter);
      }
      }
      #endif

      // Send the ACK for the actual payload
      AckMessage ack_msg;
      ack_msg.counter = msg->counter;
      ack_msg.success = true;
      esp_now_send(addr, (uint8_t *)&ack_msg, sizeof(ack_msg));
    }
}
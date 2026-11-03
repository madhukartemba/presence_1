#pragma once

#include <cstddef>
#include <cstdint>

// eternal_nrf BTHome v2 service data (bytes after UUID 0xFCD2):
//   0x40 info, 0x01 battery u8, 0x02 temp i16, 0x03 humidity u16,
//   0x0F button u8, 0x11 opening u8.
struct EternalBthome {
  bool ok = false;
  bool has_battery = false;
  bool has_temp = false;
  bool has_hum = false;
  bool has_button = false;
  bool has_opening = false;
  float battery = 0;
  float temp_c = 0;
  float humidity = 0;
  bool button = false;
  bool opening = false;
};

inline EternalBthome parse_eternal_bthome(const uint8_t *data, size_t len) {
  EternalBthome reading;
  if (data == nullptr || len < 2 || data[0] != 0x40) {
    return reading;
  }
  size_t i = 1;
  while (i < len) {
    const uint8_t oid = data[i++];
    size_t need = 0;
    switch (oid) {
      case 0x01:
      case 0x0F:
      case 0x11:
        need = 1;
        break;
      case 0x02:
      case 0x03:
        need = 2;
        break;
      default:
        return reading;
    }
    if (i + need > len) {
      return reading;
    }
    if (oid == 0x01) {
      reading.battery = data[i];
      reading.has_battery = true;
    } else if (oid == 0x02) {
      const int16_t raw = static_cast<int16_t>(data[i] | (data[i + 1] << 8));
      reading.temp_c = raw / 100.0f;
      reading.has_temp = true;
    } else if (oid == 0x03) {
      const uint16_t raw = static_cast<uint16_t>(data[i] | (data[i + 1] << 8));
      reading.humidity = raw / 100.0f;
      reading.has_hum = true;
    } else if (oid == 0x0F) {
      reading.button = data[i] != 0;
      reading.has_button = true;
    } else if (oid == 0x11) {
      reading.opening = data[i] != 0;
      reading.has_opening = true;
    }
    i += need;
    reading.ok = true;
  }
  return reading;
}

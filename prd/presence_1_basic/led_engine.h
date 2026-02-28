#pragma once

#include "esphome.h"
#include "esphome/components/network/util.h"
#include <LiteLED.h>
#include <cmath> // Added for expf, pow, etc.

using namespace esphome;

#define LED_PIN 6
#define LED_COUNT 5
#define MAX_PULSE_COLORS 8
#define PULSE_FRAME_INTERVAL_MS 24
#define BOOT_WIFI_FRAME_INTERVAL_MS 32
#define WIFI_CONNECT_TIMEOUT_MS 70000

// Create strip properly for LiteLED v3
LiteLED strip(LED_STRIP_WS2812, false);

enum AnimationMode {
  IDLE,
  CENTER_PULSE,
  BOOT,
  BOOT_FADE_OUT,
  WIFI_CONNECTING,
  WIFI_SUCCESS,
  WIFI_FAILURE
};

AnimationMode current_mode = IDLE;

int frame = 0;
unsigned long last_frame_ms = 0;
unsigned long wifi_connecting_start_ms = 0;

struct LedColor {
  uint8_t r, g, b;
};

LedColor pulse_colors[MAX_PULSE_COLORS];
int pulse_color_count = 1;

inline void reset_timing() {
  frame = 0;
  last_frame_ms = 0;
}

inline void show() {
  strip.show();
}

inline void clear() {
  strip.clear();
}

inline void setPixel(int i, uint8_t r, uint8_t g, uint8_t b) {
  rgb_t c = { r, g, b };   // Standard RGB order
  strip.setPixel(i, c, false);
}

void led_init() {
  strip.begin(LED_PIN, LED_COUNT);
  clear();
  show();
}

void led_play_boot() {
  current_mode = BOOT;
  reset_timing();
}

void led_play_wifi_connected() {
  current_mode = WIFI_SUCCESS;
  reset_timing();
}

void led_play_wifi_failed() {
  current_mode = WIFI_FAILURE;
  reset_timing();
}

void led_play_center_wave(const LedColor* colors, int num_colors) {
  current_mode = CENTER_PULSE;
  reset_timing();
  pulse_color_count = constrain(num_colors, 1, MAX_PULSE_COLORS);
  for (int i = 0; i < pulse_color_count; i++) {
    pulse_colors[i] = colors[i];
  }
}

void led_play_feedback_single() {
  LedColor blue = {0, 0, 255};
  led_play_center_wave(&blue, 1);
}

void led_play_feedback_double() {
  static const LedColor magenta = {255, 0, 255};
  led_play_center_wave(&magenta, 1);
}

void led_play_feedback_motion_on() {
  static const LedColor green = {0, 255, 0};
  led_play_center_wave(&green, 1);
}

void led_play_feedback_motion_off() {
  static const LedColor red = {255, 0, 0};
  led_play_center_wave(&red, 1);
}

void led_tick() {
  switch (current_mode) {

    case CENTER_PULSE: {
      const int total_frames = 80;
      const int center = 2; // Middle LED for a 5-LED strip

      if (frame >= total_frames) {
        clear(); show();
        current_mode = IDLE;
        return;
      }

      unsigned long now = millis();
      if (now - last_frame_ms < PULSE_FRAME_INTERVAL_MS) return;
      last_frame_ms = now;

      clear();

      float wave_position = frame * 0.08f;
      float width = 0.8f;

      const int fade_in_frames = 20;
      float fade_in = frame < fade_in_frames
        ? pow((float)frame / fade_in_frames, 2.0f)
        : 1.0f;

      int color_idx = (frame * pulse_color_count) / total_frames % pulse_color_count;
      LedColor base = pulse_colors[color_idx];

      for (int i = 0; i < LED_COUNT; i++) {
        float distance = abs(i - center);
        float intensity = exp(-pow(distance - wave_position, 2) / width);
        intensity = constrain(intensity, 0.0f, 1.0f) * fade_in;

        setPixel(i, base.r * intensity, base.g * intensity, base.b * intensity);
      }

      show();
      frame++;
      break;
    }

    case BOOT: {
      const int total_frames = 40;
      const LedColor boot_color = {255, 255, 255};

      if (frame >= total_frames) {
        current_mode = BOOT_FADE_OUT;
        reset_timing();
        return;
      }

      unsigned long now = millis();
      if (now - last_frame_ms < BOOT_WIFI_FRAME_INTERVAL_MS) return;
      last_frame_ms = now;

      clear();
      float progress = (float)frame * (LED_COUNT + 0.8f) / total_frames;
      for (int i = 0; i < LED_COUNT; i++) {
        float t = progress - (float)i;
        float intensity = t <= 0.0f ? 0.0f : (t >= 1.0f ? 1.0f : t * t * (3.0f - 2.0f * t));
        setPixel(i, boot_color.r * intensity, boot_color.g * intensity, boot_color.b * intensity);
      }
      show();
      frame++;
      break;
    }

    case BOOT_FADE_OUT: {
      const int fade_frames = 30;
      const LedColor boot_color = {255, 255, 255};
    
      unsigned long now = millis();
      if (now - last_frame_ms < BOOT_WIFI_FRAME_INTERVAL_MS) return;
      last_frame_ms = now;
    
      if (frame >= fade_frames) {
        clear(); show();
        current_mode = WIFI_CONNECTING;
        reset_timing();
        wifi_connecting_start_ms = millis();
        return;
      }
    
      float fade = 1.0f - ((float)frame / (float)(fade_frames - 1));
      fade = fade * fade; // Smooth ease-out
    
      for (int i = 0; i < LED_COUNT; i++) {
        setPixel(i, boot_color.r * fade, boot_color.g * fade, boot_color.b * fade);
      }
    
      show();
      frame++;
      break;
    }

    case WIFI_CONNECTING: {
      unsigned long now = millis();
      if (now - last_frame_ms < BOOT_WIFI_FRAME_INTERVAL_MS) return;
      last_frame_ms = now;

      if (network::is_connected()) {
        current_mode = WIFI_SUCCESS;
        reset_timing();
        return;
      }
      if (now - wifi_connecting_start_ms > WIFI_CONNECT_TIMEOUT_MS) {
        current_mode = WIFI_FAILURE;
        reset_timing();
        return;
      }

      clear();
      const LedColor wave_color = {0, 0, 255};
      const float wave_width = 1.2f;
      const int cycle = 32;
      const int fade_in_frames = 12;
      
      float fade_in = frame < fade_in_frames ? (float)frame / (float)fade_in_frames : 1.0f;
      fade_in = fade_in * fade_in * (3.0f - 2.0f * fade_in);
      
      int step = frame % cycle;
      float wave_pos = step < cycle / 2 ? (float)step * 0.25f : (float)(cycle - step) * 0.25f;
      
      for (int i = 0; i < LED_COUNT; i++) {
        float d = (float)i - wave_pos;
        float intensity = expf(-d * d / (wave_width * wave_width));
        intensity = constrain(intensity, 0.0f, 1.0f) * fade_in;
        setPixel(i, wave_color.r * intensity, wave_color.g * intensity, wave_color.b * intensity);
      }
      show();
      frame++;
      break;
    }

    case WIFI_SUCCESS: {
      const int total_frames = 35;
      const LedColor success_color = {0, 255, 0};

      if (frame >= total_frames) {
        clear(); show();
        current_mode = IDLE;
        return;
      }

      unsigned long now = millis();
      if (now - last_frame_ms < BOOT_WIFI_FRAME_INTERVAL_MS) return;
      last_frame_ms = now;

      clear();
      float sweep = (float)frame * (LED_COUNT + 1.5f) / (total_frames - 8);
      float fade_out = frame < total_frames - 10 ? 1.0f : 1.0f - (float)(frame - (total_frames - 10)) / 10.0f;
      fade_out = fade_out * fade_out;
      
      for (int i = 0; i < LED_COUNT; i++) {
        float t = sweep - (float)i;
        float intensity = t <= 0.0f ? 0.0f : (t >= 1.2f ? 1.0f : (t >= 1.0f ? 1.0f : t * (2.0f - t)));
        intensity *= fade_out;
        setPixel(i, success_color.r * intensity, success_color.g * intensity, success_color.b * intensity);
      }
      show();
      frame++;
      break;
    }

    case WIFI_FAILURE: {
      const int total_frames = 48;
      const LedColor fail_color = {255, 0, 30};

      if (frame >= total_frames) {
        clear(); show();
        current_mode = IDLE;
        return;
      }

      unsigned long now = millis();
      if (now - last_frame_ms < BOOT_WIFI_FRAME_INTERVAL_MS) return;
      last_frame_ms = now;

      clear();
      float pulse_phase = (float)(frame % 12) / 6.0f;
      if (pulse_phase > 1.0f) pulse_phase = 2.0f - pulse_phase;
      
      float blink = pulse_phase * pulse_phase * (3.0f - 2.0f * pulse_phase);
      blink = 0.15f + 0.85f * blink;
      
      if (frame >= total_frames - 12) blink *= 1.0f - (float)(frame - (total_frames - 12)) / 12.0f;
      
      for (int i = 0; i < LED_COUNT; i++) {
        setPixel(i, fail_color.r * blink, fail_color.g * blink, fail_color.b * blink);
      }
      show();
      frame++;
      break;
    }

    case IDLE:
    default:
      break;
  }
}
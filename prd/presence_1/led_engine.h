#include "esphome.h"
#include "esphome/components/network/util.h"
#include <NeoPixelBus.h>

using namespace esphome;

#define LED_PIN 6
#define LED_COUNT 5
#define MAX_PULSE_COLORS 8
#define PULSE_FRAME_INTERVAL_MS 24
#define BOOT_WIFI_FRAME_INTERVAL_MS 32
#define WIFI_CONNECT_TIMEOUT_MS 70000

NeoPixelBus<NeoGrbFeature, NeoEsp32Rmt0800KbpsMethod> strip(LED_COUNT, LED_PIN);

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

// Stored colors for center pulse (supports multiple)
RgbColor pulse_colors[MAX_PULSE_COLORS];
int pulse_color_count = 1;

void start_boot_animation() {
  current_mode = BOOT;
  frame = 0;
}

void start_wifi_success_animation() {
  current_mode = WIFI_SUCCESS;
  frame = 0;
}

void start_wifi_failure_animation() {
  current_mode = WIFI_FAILURE;
  frame = 0;
}

void start_center_pulse() {
  current_mode = CENTER_PULSE;
  frame = 0;
  pulse_color_count = 1;
  pulse_colors[0] = RgbColor(0, 0, 255);  // Default: blue
}

void start_center_pulse(const RgbColor* colors, int num_colors) {
  current_mode = CENTER_PULSE;
  frame = 0;
  pulse_color_count = constrain(num_colors, 1, MAX_PULSE_COLORS);
  for (int i = 0; i < pulse_color_count; i++) {
    pulse_colors[i] = colors[i];
  }
}

void led_engine_setup() {
  strip.Begin();
  strip.Show();
}

void led_engine_loop() {

  switch (current_mode) {

    case CENTER_PULSE: {
      const int total_frames = 80;
      const int center = 2;

      if (frame >= total_frames) {
        strip.ClearTo(RgbColor(0,0,0));
        strip.Show();
        current_mode = IDLE;
        return;
      }

      // Throttle: only advance frame after PULSE_FRAME_INTERVAL_MS
      unsigned long now = millis();
      if (now - last_frame_ms < PULSE_FRAME_INTERVAL_MS) {
        return;
      }
      last_frame_ms = now;

      strip.ClearTo(RgbColor(0,0,0));

      float wave_position = frame * 0.08f;
      float width = 0.8f;

      // Fade-in: ease-in over first ~20 frames so center doesn't appear abruptly
      const int fade_in_frames = 20;
      float fade_in = frame < fade_in_frames
        ? pow((float)frame / fade_in_frames, 2.0f)  // quadratic ease-in
        : 1.0f;

      // Cycle through colors over the animation duration
      int color_idx = (frame * pulse_color_count) / total_frames % pulse_color_count;
      RgbColor base = pulse_colors[color_idx];

      for (int i = 0; i < LED_COUNT; i++) {
        float distance = abs(i - center);
        float intensity = exp(-pow(distance - wave_position, 2) / width);
        intensity = constrain(intensity, 0.0f, 1.0f) * fade_in;

        strip.SetPixelColor(i, RgbColor(
          base.R * intensity,
          base.G * intensity,
          base.B * intensity
        ));
      }

      strip.Show();
      frame++;
      break;
    }

    case BOOT: {
      // Smooth fill: progress 0..5 sweeps left to right with per-LED fade-in
      const int total_frames = 40;
      const RgbColor boot_color(60, 80, 120);

      if (frame >= total_frames) {
        current_mode = BOOT_FADE_OUT;
        frame = 0;
        return;
      }

      unsigned long now = millis();
      if (now - last_frame_ms < BOOT_WIFI_FRAME_INTERVAL_MS) return;
      last_frame_ms = now;

      strip.ClearTo(RgbColor(0,0,0));
      float progress = (float)frame * (LED_COUNT + 0.8f) / total_frames;
      for (int i = 0; i < LED_COUNT; i++) {
        float t = progress - (float)i;
        float intensity = t <= 0.0f ? 0.0f : (t >= 1.0f ? 1.0f : t * t * (3.0f - 2.0f * t));
        strip.SetPixelColor(i, RgbColor(
          (uint8_t)(boot_color.R * intensity),
          (uint8_t)(boot_color.G * intensity),
          (uint8_t)(boot_color.B * intensity)
        ));
      }
      strip.Show();
      frame++;
      break;
    }

    case BOOT_FADE_OUT: {
        const int fade_frames = 30;
        const RgbColor boot_color(60, 80, 120);
      
        unsigned long now = millis();
        if (now - last_frame_ms < BOOT_WIFI_FRAME_INTERVAL_MS) return;
        last_frame_ms = now;
      
        if (frame >= fade_frames) {
          strip.ClearTo(RgbColor(0, 0, 0));
          strip.Show();
          current_mode = WIFI_CONNECTING;
          frame = 0;
          wifi_connecting_start_ms = millis();
          return;
        }
      
        // Smooth fade from 1.0 → 0.0
        float fade = 1.0f - ((float)frame / (float)(fade_frames - 1));
      
        // Smooth ease-out
        fade = fade * fade;
      
        for (int i = 0; i < LED_COUNT; i++) {
          strip.SetPixelColor(i, RgbColor(
            (uint8_t)(boot_color.R * fade),
            (uint8_t)(boot_color.G * fade),
            (uint8_t)(boot_color.B * fade)
          ));
        }
      
        strip.Show();
        frame++;
        break;
      }
      

    case WIFI_CONNECTING: {
      // Fade in from black, then wave traveling left-right (blue crest)
      unsigned long now = millis();
      if (now - last_frame_ms < BOOT_WIFI_FRAME_INTERVAL_MS) return;
      last_frame_ms = now;

      if (network::is_connected()) {
        current_mode = WIFI_SUCCESS;
        frame = 0;
        return;
      }
      if (now - wifi_connecting_start_ms > WIFI_CONNECT_TIMEOUT_MS) {
        current_mode = WIFI_FAILURE;
        frame = 0;
        return;
      }

      strip.ClearTo(RgbColor(0,0,0));
      const RgbColor wave_color(0, 0, 255);
      const float wave_width = 1.2f;
      const int cycle = 32;
      const int fade_in_frames = 12;
      float fade_in = frame < fade_in_frames
        ? (float)frame / (float)fade_in_frames
        : 1.0f;
      fade_in = fade_in * fade_in * (3.0f - 2.0f * fade_in);
      int step = frame % cycle;
      float wave_pos = step < cycle / 2
        ? (float)step * 0.25f
        : (float)(cycle - step) * 0.25f;
      for (int i = 0; i < LED_COUNT; i++) {
        float d = (float)i - wave_pos;
        float intensity = expf(-d * d / (wave_width * wave_width));
        intensity = constrain(intensity, 0.0f, 1.0f) * fade_in;
        strip.SetPixelColor(i, RgbColor(
          (uint8_t)(wave_color.R * intensity),
          (uint8_t)(wave_color.G * intensity),
          (uint8_t)(wave_color.B * intensity)
        ));
      }
      strip.Show();
      frame++;
      break;
    }

    case WIFI_SUCCESS: {
      // Smooth green sweep with soft falloff then fade out
      const int total_frames = 35;
      const RgbColor success_color(0, 255, 0);

      if (frame >= total_frames) {
        strip.ClearTo(RgbColor(0,0,0));
        strip.Show();
        current_mode = IDLE;
        return;
      }

      unsigned long now = millis();
      if (now - last_frame_ms < BOOT_WIFI_FRAME_INTERVAL_MS) return;
      last_frame_ms = now;

      strip.ClearTo(RgbColor(0,0,0));
      float sweep = (float)frame * (LED_COUNT + 1.5f) / (total_frames - 8);
      float fade_out = frame < total_frames - 10 ? 1.0f : 1.0f - (float)(frame - (total_frames - 10)) / 10.0f;
      fade_out = fade_out * fade_out;
      for (int i = 0; i < LED_COUNT; i++) {
        float t = sweep - (float)i;
        float intensity = t <= 0.0f ? 0.0f : (t >= 1.2f ? 1.0f : (t >= 1.0f ? 1.0f : t * (2.0f - t)));
        intensity *= fade_out;
        strip.SetPixelColor(i, RgbColor(
          (uint8_t)(success_color.R * intensity),
          (uint8_t)(success_color.G * intensity),
          (uint8_t)(success_color.B * intensity)
        ));
      }
      strip.Show();
      frame++;
      break;
    }

    case WIFI_FAILURE: {
      // Smooth red pulse twice then fade out
      const int total_frames = 48;
      const RgbColor fail_color(255, 0, 30);

      if (frame >= total_frames) {
        strip.ClearTo(RgbColor(0,0,0));
        strip.Show();
        current_mode = IDLE;
        return;
      }

      unsigned long now = millis();
      if (now - last_frame_ms < BOOT_WIFI_FRAME_INTERVAL_MS) return;
      last_frame_ms = now;

      strip.ClearTo(RgbColor(0,0,0));
      float pulse_phase = (float)(frame % 12) / 6.0f;
      if (pulse_phase > 1.0f) pulse_phase = 2.0f - pulse_phase;
      float blink = pulse_phase * pulse_phase * (3.0f - 2.0f * pulse_phase);
      blink = 0.15f + 0.85f * blink;
      if (frame >= total_frames - 12) blink *= 1.0f - (float)(frame - (total_frames - 12)) / 12.0f;
      for (int i = 0; i < LED_COUNT; i++) {
        strip.SetPixelColor(i, RgbColor(
          (uint8_t)(fail_color.R * blink),
          (uint8_t)(fail_color.G * blink),
          (uint8_t)(fail_color.B * blink)
        ));
      }
      strip.Show();
      frame++;
      break;
    }

    case IDLE:
    default:
      break;
  }
}

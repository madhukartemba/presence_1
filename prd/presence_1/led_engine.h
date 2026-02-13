#include "esphome.h"
#include <NeoPixelBus.h>

using namespace esphome;

#define LED_PIN 6
#define LED_COUNT 5
#define MAX_PULSE_COLORS 8
#define PULSE_FRAME_INTERVAL_MS 24

NeoPixelBus<NeoGrbFeature, NeoEsp32Rmt0800KbpsMethod> strip(LED_COUNT, LED_PIN);

enum AnimationMode {
  IDLE,
  CENTER_PULSE
};

AnimationMode current_mode = IDLE;
int frame = 0;
unsigned long last_pulse_frame_ms = 0;

// Stored colors for center pulse (supports multiple)
RgbColor pulse_colors[MAX_PULSE_COLORS];
int pulse_color_count = 1;

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
      if (now - last_pulse_frame_ms < PULSE_FRAME_INTERVAL_MS) {
        return;
      }
      last_pulse_frame_ms = now;

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

    case IDLE:
    default:
      break;
  }
}

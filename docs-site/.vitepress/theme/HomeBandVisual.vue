<script setup lang="ts">
// Decorative animated illustration for each home-page capability band.
// Static trusted markup (no user input), rendered via v-html into an SVG
// shell; motion comes from CSS classes in theme/style.css and is fully
// disabled under prefers-reduced-motion.
defineProps<{ variant?: string }>();

const scenes: Record<string, string> = {
  // Torana arch with traffic flowing through it.
  proxying: `
    <path class="bv-line" d="M44 78V44c0-14 11-24 28-24h16c17 0 28 10 28 24v34"/>
    <path class="bv-dash bv-teal" d="M6 62h208"/>
    <g class="bv-flow"><circle class="bv-dot" cx="14" cy="62" r="4"/></g>`,

  // Request/response flows with a sliding control knob.
  reqresp: `
    <path class="bv-dash" d="M14 26h186"/>
    <path class="bv-line" d="M198 20l12 6-12 6"/>
    <path class="bv-dash bv-teal bv-march-r" d="M14 58h186"/>
    <path class="bv-line" d="M22 52l-12 6 12 6"/>
    <g class="bv-slide"><circle class="bv-dot" cx="76" cy="58" r="7"/></g>`,

  // Circle, square, triangle tokens with translating dashes between them.
  translation: `
    <circle class="bv-line" cx="34" cy="42" r="15"/>
    <rect class="bv-line" x="94" y="27" width="30" height="30" rx="6"/>
    <path class="bv-line" d="M154 57l15-25 15 25z"/>
    <path class="bv-dash bv-teal" d="M52 42h36m44 0h18"/>`,

  // Gauge with a sweeping needle.
  traffic: `
    <path class="bv-line" d="M58 64a52 52 0 0 1 104 0"/>
    <path class="bv-line" d="M50 64h14M156 64h14"/>
    <g class="bv-needle">
      <path class="bv-teal bv-stroke2" d="M110 64l26-22"/>
      <circle class="bv-dot" cx="110" cy="64" r="4"/>
    </g>`,

  // Shield with a scanning pulse and a key.
  security: `
    <path class="bv-line" d="M56 10 24 24v20c0 19 14 30 32 36 18-6 32-17 32-36V24L56 10Z"/>
    <circle class="bv-ringpulse" cx="56" cy="40" r="17"/>
    <circle class="bv-line" cx="128" cy="40" r="9"/>
    <path class="bv-dash bv-teal" d="M137 40h58"/>
    <path class="bv-teal" d="M180 40v12M191 40v8"/>`,

  // Sparkle with an orbiting pair of agents.
  ai: `
    <path class="bv-teal" d="M110 24l5 13 13 5-13 5-5 13-5-13-13-5 13-5 5-13Z"/>
    <circle class="bv-dash" cx="110" cy="42" r="30"/>
    <g class="bv-orbit">
      <circle class="bv-dot" cx="140" cy="42" r="4"/>
      <circle class="bv-dot bv-dim" cx="80" cy="42" r="3"/>
    </g>`,

  // Socket and a plug easing in and out.
  extensibility: `
    <rect class="bv-line" x="16" y="28" width="46" height="28" rx="7"/>
    <path class="bv-line" d="M62 36h16M62 48h16"/>
    <g class="bv-plug">
      <rect class="bv-teal" x="96" y="28" width="42" height="28" rx="7"/>
      <path class="bv-teal" d="M138 36h14M138 48h14"/>
    </g>
    <path class="bv-dash" d="M162 42h34"/>`,

  // Self-drawing heartbeat plus growing bars.
  observability: `
    <path class="bv-draw bv-teal" d="M8 46h30l10-24 14 44 12-28 8 8h24"/>
    <path class="bv-bar" d="M148 66V52"/>
    <path class="bv-bar" d="M164 66V36"/>
    <path class="bv-bar" d="M180 66V44"/>
    <path class="bv-bar" d="M196 66V28"/>`,

  // Circular reload arrow with marching dashes.
  operations: `
    <g class="bv-spin">
      <path class="bv-dash bv-teal" d="M136 42a28 28 0 1 1-8-20"/>
      <path class="bv-teal" d="M132 12v14h-14"/>
    </g>
    <circle class="bv-dot" cx="110" cy="42" r="5"/>
    <path class="bv-dash" d="M156 42h52M110 78H52"/>`,

  // Hub radiating generations to satellite edges.
  fleet: `
    <circle class="bv-dot" cx="110" cy="42" r="6"/>
    <circle class="bv-ringpulse" cx="110" cy="42" r="18"/>
    <path class="bv-dash" d="M34 16 110 42M34 68 110 42M186 42 110 42"/>
    <circle class="bv-dot bv-dim" cx="34" cy="16" r="4"/>
    <circle class="bv-dot bv-dim" cx="34" cy="68" r="4"/>
    <circle class="bv-dot bv-dim" cx="186" cy="42" r="4"/>`,
};
</script>

<template>
  <svg
    v-if="variant && scenes[variant]"
    class="band-visual"
    viewBox="0 0 220 84"
    fill="none"
    aria-hidden="true"
    v-html="scenes[variant]"
  ></svg>
</template>

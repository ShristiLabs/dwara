<script setup lang="ts">
// Home hero mark: the Dwara torana symbol with a soft glow, a slow float,
// and expanding ripple rings (traffic radiating through the gateway).
// All motion is disabled under `prefers-reduced-motion: reduce` via CSS.
import { withBase } from "vitepress";
</script>

<template>
  <div class="hero-mark">
    <span class="hero-glow" aria-hidden="true"></span>
    <span class="hero-ring r1" aria-hidden="true"></span>
    <span class="hero-ring r2" aria-hidden="true"></span>
    <img
      class="hero-mark-img"
      :src="withBase('/mark-color.svg')"
      alt="Dwara torana gateway mark"
    />
  </div>
</template>

<script setup lang="ts">
// Wraps the default VitePress Layout to customize the home page:
// - `home-hero-image`: the Dwara torana mark with glow + ripple rings
// - `home-hero-actions-after`: a badge strip under the CTA buttons
//
// Also wires the scroll-reveal motion for home-page sections. Motion is
// opt-in at runtime: classes are added from JS only, so the SSG output
// (and no-JS browsers) render everything fully visible. Users with
// `prefers-reduced-motion: reduce` get no animation at all.
import { nextTick, onMounted, watch } from "vue";
import { useRoute } from "vitepress";
import DefaultTheme from "vitepress/theme";
import HomeHeroImage from "./HomeHeroImage.vue";

const { Layout } = DefaultTheme;
const route = useRoute();

function applyHomeMotion() {
  if (typeof document === "undefined") return;
  if (window.matchMedia("(prefers-reduced-motion: reduce)").matches) return;

  const home = document.querySelector(".VPHome");
  if (!home) return;

  // Staggered entrance for the feature cards (above the fold).
  const features = home.querySelectorAll<HTMLElement>(".VPFeature");
  features.forEach((el, i) => {
    el.classList.add("feature-enter");
    el.style.animationDelay = `${Math.min(i, 11) * 45}ms`;
  });

  // Scroll-triggered reveal for the content sections below the cards.
  // The page content may be nested inside single-child wrapper divs
  // (versioning plugin etc.), so descend to the first level that holds
  // the actual sections. Individual capability bands reveal one by one.
  let contentRoot: Element | null = home.querySelector(".vp-doc");
  while (contentRoot && contentRoot.children.length === 1) {
    contentRoot = contentRoot.firstElementChild;
  }
  const targets = contentRoot
    ? [...contentRoot.children, ...home.querySelectorAll<HTMLElement>(".home-band")]
    : [];
  if (!targets.length) return;

  home.classList.add("motion-ready");
  const io = new IntersectionObserver(
    (entries) => {
      for (const entry of entries) {
        if (entry.isIntersecting) {
          entry.target.classList.add("revealed");
          io.unobserve(entry.target);
        }
      }
    },
    { rootMargin: "0px 0px -10% 0px", threshold: 0.05 },
  );
  targets.forEach((el) => {
    el.classList.add("reveal");
    io.observe(el);
  });
}

onMounted(() => {
  applyHomeMotion();
  // The Layout component persists across SPA navigations; re-apply when
  // the home page is (re)entered.
  watch(
    () => route.path,
    () => nextTick(applyHomeMotion),
  );
});
</script>

<template>
  <Layout>
    <template #home-hero-image>
      <HomeHeroImage />
    </template>
    <template #home-hero-actions-after>
      <div class="home-badges">
        <span class="home-badge">Single Rust binary</span>
        <span class="home-badge">Zero-buffer streaming</span>
        <span class="home-badge">Declarative YAML</span>
      </div>
    </template>
  </Layout>
</template>

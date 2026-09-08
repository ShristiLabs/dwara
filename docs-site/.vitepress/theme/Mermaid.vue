<template>
  <div class="mermaid-wrap">
    <!-- Inline toolbar: zoom controls + maximize button -->
    <div class="mermaid-tools" v-if="svg">
      <button
        class="mermaid-btn"
        title="Zoom in"
        @click="zoomIn"
        aria-label="Zoom in"
      >
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round">
          <line x1="12" y1="5" x2="12" y2="19" />
          <line x1="5" y1="12" x2="19" y2="12" />
        </svg>
      </button>
      <button
        class="mermaid-btn"
        title="Zoom out"
        @click="zoomOut"
        aria-label="Zoom out"
      >
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round">
          <line x1="5" y1="12" x2="19" y2="12" />
        </svg>
      </button>
      <button
        class="mermaid-btn"
        title="Reset zoom"
        @click="zoomReset"
        aria-label="Reset zoom"
      >
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
          <path d="M3 12a9 9 0 1 0 9-9" />
          <path d="M3 4v5h5" />
        </svg>
      </button>
      <span class="mermaid-zoom-label">{{ Math.round(scale * 100) }}%</span>
      <span class="mermaid-tools-sep"></span>
      <button
        class="mermaid-btn"
        title="Open in full screen"
        @click="openFullscreen"
        aria-label="Open in full screen"
      >
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
          <path d="M8 3H5a2 2 0 0 0-2 2v3" />
          <path d="M21 8V5a2 2 0 0 0-2-2h-3" />
          <path d="M3 16v3a2 2 0 0 0 2 2h3" />
          <path d="M16 21h3a2 2 0 0 0 2-2v-3" />
        </svg>
      </button>
    </div>
    <div
      ref="viewport"
      class="mermaid-viewport"
      @wheel="onWheel"
    >
      <div
        class="mermaid-inner"
        :class="props.class"
        :style="innerStyle"
        v-html="svg"
      ></div>
    </div>

    <!-- Fullscreen overlay -->
    <Teleport to="body">
      <div v-if="fullscreen" class="mermaid-overlay" @keydown.esc="closeFullscreen" tabindex="-1">
        <div class="mermaid-overlay-toolbar">
          <button
            class="mermaid-btn"
            title="Zoom in"
            @click="zoomIn"
            aria-label="Zoom in"
          >
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round">
              <line x1="12" y1="5" x2="12" y2="19" />
              <line x1="5" y1="12" x2="19" y2="12" />
            </svg>
          </button>
          <button
            class="mermaid-btn"
            title="Zoom out"
            @click="zoomOut"
            aria-label="Zoom out"
          >
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round">
              <line x1="5" y1="12" x2="19" y2="12" />
            </svg>
          </button>
          <button
            class="mermaid-btn"
            title="Reset zoom"
            @click="zoomReset"
            aria-label="Reset zoom"
          >
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
              <path d="M3 12a9 9 0 1 0 9-9" />
              <path d="M3 4v5h5" />
            </svg>
          </button>
          <span class="mermaid-zoom-label">{{ Math.round(scale * 100) }}%</span>
          <span class="mermaid-tools-sep"></span>
          <button
            class="mermaid-btn"
            title="Close full screen"
            @click="closeFullscreen"
            aria-label="Close full screen"
          >
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
              <path d="M8 3v3a2 2 0 0 1-2 2H3" />
              <path d="M21 8h-3a2 2 0 0 1-2-2V3" />
              <path d="M3 16h3a2 2 0 0 1 2 2v3" />
              <path d="M16 21v-3a2 2 0 0 1 2-2h3" />
            </svg>
          </button>
        </div>
        <div
          ref="overlayViewport"
          class="mermaid-overlay-viewport"
          @wheel="onWheel"
        >
          <div
            class="mermaid-inner"
            :class="props.class"
            :style="innerStyle"
            v-html="svg"
          ></div>
        </div>
      </div>
    </Teleport>
  </div>
</template>

<script setup>
import { onMounted, onUnmounted, ref, toRaw, computed, nextTick } from "vue";
import { useData } from "vitepress";
import mermaid from "mermaid";

// Mermaid settings (mirrors vitepress-plugin-mermaid defaults).
const pluginSettings = ref({
  securityLevel: "loose",
  startOnLoad: false,
  externalDiagrams: [],
});
const { page } = useData();
const { frontmatter } = toRaw(page.value);
const mermaidPageTheme = frontmatter.mermaidTheme || "";

const props = defineProps({
  graph: {
    type: String,
    required: true,
  },
  id: {
    type: String,
    required: true,
  },
  class: {
    type: String,
    required: false,
    default: "mermaid",
  },
});

const svg = ref(null);
const viewport = ref(null);
const overlayViewport = ref(null);
const scale = ref(1);
const fullscreen = ref(false);
const MIN_SCALE = 0.3;
const MAX_SCALE = 5;
let mut = null;

const innerStyle = computed(() => ({
  transform: `scale(${scale.value})`,
  transformOrigin: "top left",
}));

onMounted(async () => {
  // Load optional config provided by vitepress-plugin-mermaid via the
  // virtual module. Fall back to defaults if unavailable.
  try {
    let settings = await import("virtual:mermaid-config");
    if (settings?.default) pluginSettings.value = settings.default;
  } catch {
    // virtual module not present; defaults are fine
  }

  mut = new MutationObserver(async () => await renderChart());
  mut.observe(document.documentElement, { attributes: true });
  await renderChart();

  // Refresh images on first render (mirrors upstream plugin behaviour).
  const hasImages =
    /<img([\w\W]+?)>/.exec(decodeURIComponent(props.graph))?.length > 0;
  if (hasImages)
    setTimeout(() => {
      let imgElements = document.getElementsByTagName("img");
      let imgs = Array.from(imgElements);
      if (imgs.length) {
        Promise.all(
          imgs
            .filter((img) => !img.complete)
            .map(
              (img) =>
                new Promise((resolve) => {
                  img.onload = img.onerror = resolve;
                })
            )
        ).then(async () => {
          await renderChart();
        });
      }
    }, 100);
});

onUnmounted(() => mut?.disconnect());

// Post-process the mermaid SVG to fix multi-line label clipping.
//
// Mermaid computes the SVG height/viewBox from its layout engine, but
// nodes with \n multi-line labels can extend past the computed bounds.
// The SVG's default overflow:hidden then clips the last line. We fix
// this at the SVG coordinate level by:
//   1. Measuring the actual content bounds via getBBox
//   2. Expanding the viewBox and height to fit the real content + padding
//   3. Stripping the constraining max-width inline style
//   4. Setting overflow:visible as a belt-and-suspenders measure
const fixSvgClipping = (svgCode) => {
  try {
    const parser = new DOMParser();
    const doc = parser.parseFromString(svgCode, "image/svg+xml");
    const svgEl = doc.documentElement;
    if (!svgEl || svgEl.tagName.toLowerCase() !== "svg") return svgCode;

    // Strip max-width style that constrains the SVG and can cause
    // text to overflow when the diagram is scaled down.
    const style = svgEl.getAttribute("style") || "";
    if (style) {
      const cleaned = style
        .replace(/max-width\s*:\s*[^;]+;?/gi, "")
        .replace(/\s{2,}/g, " ")
        .trim();
      if (cleaned) svgEl.setAttribute("style", cleaned);
      else svgEl.removeAttribute("style");
    }

    // Ensure overflow is visible so content outside the viewBox renders.
    svgEl.setAttribute("overflow", "visible");

    // Read the current viewBox and height.
    const viewBoxAttr = svgEl.getAttribute("viewBox");
    const heightAttr = svgEl.getAttribute("height");

    // Parse viewBox: "minX minY width height"
    let vbX = 0,
      vbY = 0,
      vbW = 0,
      vbH = 0;
    if (viewBoxAttr) {
      const parts = viewBoxAttr.split(/[\s,]+/).map(Number);
      if (parts.length === 4) [vbX, vbY, vbW, vbH] = parts;
    }

    // Add vertical padding (in SVG user units) to give multi-line labels
    // room. 24 units is roughly one extra text line at default font size.
    const PAD = 24;

    // Expand viewBox height and SVG height attribute to include padding.
    if (viewBoxAttr) {
      svgEl.setAttribute(
        "viewBox",
        `${vbX} ${vbY} ${vbW} ${vbH + PAD}`,
      );
    }
    if (heightAttr) {
      const h = parseFloat(heightAttr);
      if (!isNaN(h)) svgEl.setAttribute("height", String(h + PAD));
    }

    return new XMLSerializer().serializeToString(svgEl);
  } catch {
    // If post-processing fails, return the original SVG unchanged.
    return svgCode;
  }
};

// DOM-level post-processing: expand individual node containers that clip
// multi-line labels. Mermaid's flowchart nodes use <foreignObject> (HTML
// labels) or <text>/<tspan> (SVG labels) inside a <rect>/<polygon> shape.
// The shape height is computed by the layout engine and sometimes
// underestimates the last line, clipping it. We measure the actual content
// and expand both the content container and the node shape.
const fixNodeClipping = (root) => {
  if (!root) return;
  const svgEl = root.querySelector("svg");
  if (!svgEl) return;

  // --- foreignObject (HTML labels, default for flowchart) ---
  const foreignObjects = svgEl.querySelectorAll("foreignObject");
  for (const fo of foreignObjects) {
    const inner = fo.firstElementChild;
    if (!inner) continue;
    // scrollHeight includes overflow; offsetHeight is the visible box.
    const contentH = inner.scrollHeight || inner.offsetHeight || 0;
    const foH = parseFloat(fo.getAttribute("height") || "0");
    if (contentH > foH) {
      const newH = contentH + 2; // small breathing room
      const dy = newH - foH;
      fo.setAttribute("height", String(newH));
      // Expand the sibling node shape (rect, polygon, circle) to match.
      const shape = fo.parentElement?.querySelector("rect, polygon, circle, path");
      if (shape) {
        const sh = parseFloat(shape.getAttribute("height") || "0");
        if (sh > 0) shape.setAttribute("height", String(sh + dy));
      }
    }
  }

  // --- SVG text labels (htmlLabels: false, or non-flowchart diagrams) ---
  // For text-based labels, check if the last tspan extends beyond the
  // node shape and expand the shape if so.
  const textEls = svgEl.querySelectorAll("text");
  for (const textEl of textEls) {
    try {
      const bbox = textEl.getBBox();
      const parent = textEl.parentElement;
      if (!parent) continue;
      const shape = parent.querySelector("rect, polygon, circle");
      if (!shape) continue;
      const sh = parseFloat(shape.getAttribute("height") || "0");
      const sy = parseFloat(shape.getAttribute("y") || "0");
      if (sh <= 0) continue;
      const textBottom = bbox.y + bbox.height;
      const shapeBottom = sy + sh;
      if (textBottom > shapeBottom) {
        const dy = textBottom - shapeBottom + 2;
        shape.setAttribute("height", String(sh + dy));
      }
    } catch {
      // getBBox can throw if the element is not rendered
    }
  }
};

const renderChart = async () => {
  const hasDarkClass = document.documentElement.classList.contains("dark");
  let mermaidConfig = { ...pluginSettings.value };

  if (mermaidPageTheme) mermaidConfig.theme = mermaidPageTheme;
  if (hasDarkClass) mermaidConfig.theme = "dark";

  try {
    mermaid.initialize(mermaidConfig);
    const { svg: svgCode } = await mermaid.render(
      props.id,
      decodeURIComponent(props.graph)
    );
    const fixed = fixSvgClipping(svgCode);
    // Force v-html re-render on theme switch (upstream hack).
    const salt = Math.random().toString(36).substring(7);
    svg.value = `${fixed} <span style="display: none">${salt}</span>`;
    // After the DOM updates, fix individual node clipping in both the
    // inline viewport and the overlay (if open).
    await nextTick();
    fixNodeClipping(viewport.value);
    if (fullscreen.value) fixNodeClipping(overlayViewport.value);
  } catch (e) {
    svg.value = `<pre style="color:var(--vp-c-danger-1)">${e}</pre>`;
  }
};

const clamp = (v) => Math.min(MAX_SCALE, Math.max(MIN_SCALE, v));

const zoomIn = () => {
  scale.value = clamp(+(scale.value + 0.2).toFixed(2));
};
const zoomOut = () => {
  scale.value = clamp(+(scale.value - 0.2).toFixed(2));
};
const zoomReset = () => {
  scale.value = 1;
  const vp = fullscreen.value ? overlayViewport.value : viewport.value;
  if (vp) {
    vp.scrollTop = 0;
    vp.scrollLeft = 0;
  }
};

const onWheel = (e) => {
  if (!e.ctrlKey && !e.metaKey) return; // only zoom with Ctrl/Cmd+wheel
  e.preventDefault();
  const delta = e.deltaY > 0 ? -0.1 : 0.1;
  scale.value = clamp(+(scale.value + delta).toFixed(2));
};

// --- Fullscreen overlay ---
let savedScale = 1;

const openFullscreen = async () => {
  savedScale = scale.value;
  fullscreen.value = true;
  // Prevent body scroll while overlay is open.
  document.body.style.overflow = "hidden";
  await nextTick();
  fixNodeClipping(overlayViewport.value);
  // Focus the overlay so Esc works.
  const overlay = document.querySelector(".mermaid-overlay");
  if (overlay) overlay.focus();
};

const closeFullscreen = () => {
  fullscreen.value = false;
  scale.value = savedScale;
  document.body.style.overflow = "";
};
</script>

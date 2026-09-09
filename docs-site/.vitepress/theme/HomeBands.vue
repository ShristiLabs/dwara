<script setup lang="ts">
// Home-page capability bands: one band per documentation domain, mirroring
// the guide sidebar groups. Reads its data from the `domains` array in
// index.md frontmatter (via useData) so page content stays in the page and
// travels with versioned snapshots. Maturity badges reuse the sidebar's
// .vp-sb-badge tiers (partial / experimental); `ent` marks enterprise-only
// capabilities. Links are base-relative (/guide/...) + withBase().
import { computed } from "vue";
import { useData, withBase } from "vitepress";
import HomeBandVisual from "./HomeBandVisual.vue";

export interface BandItem {
  name: string;
  desc?: string;
  link?: string;
  badge?: "partial" | "experimental" | "ent";
}

export interface Domain {
  title: string;
  blurb?: string;
  link?: string;
  icon?: string;
  visual?: string;
  badge?: "ent";
  items: BandItem[];
}

const { frontmatter } = useData();
const domains = computed(() => (frontmatter.value.domains ?? []) as Domain[]);
</script>

<template>
  <div class="home-bands">
    <section v-for="d in domains" :key="d.title" class="home-band">
      <div class="home-band-top">
        <div class="home-band-meta">
          <a v-if="d.link" :href="withBase(d.link)" class="home-band-head">
            <span v-if="d.icon" class="home-band-icon" v-html="d.icon"></span>
            <span class="home-band-title">{{ d.title }}</span>
            <span v-if="d.badge" class="vp-sb-badge" :class="d.badge">enterprise</span>
            <span class="home-band-arrow" aria-hidden="true">&rarr;</span>
          </a>
          <p v-if="d.blurb" class="home-band-blurb">{{ d.blurb }}</p>
        </div>
        <HomeBandVisual v-if="d.visual" :variant="d.visual" />
      </div>
      <div class="home-band-grid">
        <a
          v-for="item in d.items"
          :key="item.name"
          :href="item.link ? withBase(item.link) : undefined"
          class="band-card"
        >
          <span class="band-card-name">
            {{ item.name }}
            <span v-if="item.badge" class="vp-sb-badge" :class="item.badge">{{
              item.badge === "ent" ? "enterprise" : item.badge
            }}</span>
          </span>
          <span v-if="item.desc" class="band-card-desc">{{ item.desc }}</span>
        </a>
      </div>
    </section>
  </div>
</template>

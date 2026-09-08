<script setup lang="ts">
// Compact feature-flag chip grid for the home page, replacing the nine
// per-category tables that used to live there. Reads its data from the
// `flagGroups` array in index.md frontmatter (via useData); full detail
// (crates, dependency chains, build recipes, maturity) lives in
// /guide/feature-reference. Links are base-relative (/guide/...) and
// passed through withBase().
import { computed } from "vue";
import { useData, withBase } from "vitepress";

export interface FlagItem {
  flag: string;
  desc: string;
  link?: string;
  status?: "wired" | "partial" | "stubbed";
}

export interface FlagGroup {
  group: string;
  items: FlagItem[];
}

const { frontmatter } = useData();
const groups = computed(() => (frontmatter.value.flagGroups ?? []) as FlagGroup[]);
</script>

<template>
  <div class="home-flags">
    <section v-for="g in groups" :key="g.group" class="home-flags-group">
      <h3>{{ g.group }}</h3>
      <div class="home-flags-grid">
        <a
          v-for="item in g.items"
          :key="item.flag"
          :href="item.link ? withBase(item.link) : undefined"
          class="flag-chip"
          :class="`status-${item.status ?? 'wired'}`"
        >
          <span class="flag-chip-head">
            <span class="flag-dot" aria-hidden="true"></span>
            <code>{{ item.flag }}</code>
          </span>
          <span class="flag-desc">{{ item.desc }}</span>
        </a>
      </div>
    </section>
    <p class="flag-legend">
      <span><span class="flag-dot wired" aria-hidden="true"></span> wired end to end</span>
      <span><span class="flag-dot partial" aria-hidden="true"></span> partially wired</span>
      <span><span class="flag-dot stubbed" aria-hidden="true"></span> runtime stubbed</span>
      &mdash; see the
      <a :href="withBase('/guide/feature-reference')">feature reference</a> for dependency
      chains, build recipes, and maturity detail.
    </p>
  </div>
</template>

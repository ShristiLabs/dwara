<script setup lang="ts">
// "One gateway..." edition cards for the home page. Reads its data from
// the `editions` array in index.md frontmatter (via useData) so page
// content stays in the page and travels with versioned snapshots.
// Links are base-relative (/guide/...) and passed through withBase().
import { computed } from "vue";
import { useData, withBase } from "vitepress";

export interface EditionCard {
  title: string;
  tagline: string;
  points: string[];
  link: string;
  linkText: string;
  highlight?: boolean;
}

const { frontmatter } = useData();
const cards = computed(() => (frontmatter.value.editions ?? []) as EditionCard[]);
</script>

<template>
  <div class="home-editions">
    <a
      v-for="card in cards"
      :key="card.title"
      :href="withBase(card.link)"
      class="edition-card"
      :class="{ highlight: card.highlight }"
    >
      <h3>{{ card.title }}</h3>
      <p>{{ card.tagline }}</p>
      <ul>
        <li v-for="point in card.points" :key="point">{{ point }}</li>
      </ul>
      <span class="edition-cta">{{ card.linkText }} &rarr;</span>
    </a>
  </div>
</template>

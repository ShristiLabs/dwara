<script setup lang="ts">
// Home-page persona cards: one card per audience, mirroring the
// "Built for your team" pattern from dvarahq.com. Reads its data from
// the `personas` array in index.md frontmatter (via useData). Each
// card has an icon, a title, a blurb, and up to three guide links.
import { computed } from "vue";
import { useData, withBase } from "vitepress";

export interface PersonaLink {
  text: string;
  link: string;
}

export interface Persona {
  title: string;
  icon?: string;
  blurb?: string;
  links?: PersonaLink[];
}

const { frontmatter } = useData();
const personas = computed(() => (frontmatter.value.personas ?? []) as Persona[]);
</script>

<template>
  <div class="home-personas">
    <div v-for="p in personas" :key="p.title" class="persona-card">
      <span v-if="p.icon" class="persona-icon" v-html="p.icon"></span>
      <h3 class="persona-title">{{ p.title }}</h3>
      <p v-if="p.blurb" class="persona-blurb">{{ p.blurb }}</p>
      <div v-if="p.links?.length" class="persona-links">
        <a
          v-for="l in p.links"
          :key="l.text"
          :href="withBase(l.link)"
          class="persona-link"
        >{{ l.text }} &rarr;</a>
      </div>
    </div>
  </div>
</template>

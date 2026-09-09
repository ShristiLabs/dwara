<script setup lang="ts">
// Home-page FAQ accordion. Reads Q/A pairs from the `faq` array in
// index.md frontmatter (via useData). Pure JS toggle (no native
// <details>) so the single-open rule is deterministic. The first
// item is open by default.
import { computed, ref } from "vue";
import { useData } from "vitepress";

export interface FaqItem {
  q: string;
  a: string;
}

const { frontmatter } = useData();
const faqs = computed(() => (frontmatter.value.faq ?? []) as FaqItem[]);

const openIndex = ref(0);

function toggle(i: number) {
  openIndex.value = openIndex.value === i ? -1 : i;
}
</script>

<template>
  <div class="home-faq">
    <div
      v-for="(item, i) in faqs"
      :key="i"
      class="faq-item"
      :class="{ 'faq-item-open': openIndex === i }"
    >
      <button
        type="button"
        class="faq-q"
        :aria-expanded="openIndex === i"
        @click="toggle(i)"
      >
        <span class="faq-q-text">{{ item.q }}</span>
        <span class="faq-chevron" aria-hidden="true"></span>
      </button>
      <div class="faq-a" :class="{ 'faq-a-open': openIndex === i }">
        <p>{{ item.a }}</p>
      </div>
    </div>
  </div>
</template>

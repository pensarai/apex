<script setup lang="ts">
const route = useRoute();
const post = await $fetch(`/api/blog/posts/${route.params.slug}`);
</script>

<template><main>{{ post }}</main></template>

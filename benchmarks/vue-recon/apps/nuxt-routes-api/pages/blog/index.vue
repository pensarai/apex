<script setup lang="ts">
const posts = await useFetch("/api/blog/posts");
</script>

<template><main>{{ posts }}</main></template>

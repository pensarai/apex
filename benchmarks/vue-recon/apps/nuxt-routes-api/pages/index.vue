<script setup lang="ts">
const { data } = await useFetch("/api/me");
</script>

<template><main>{{ data }}</main></template>

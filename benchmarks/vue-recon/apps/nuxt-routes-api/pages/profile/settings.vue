<script setup lang="ts">
const settings = await useFetch("/api/profile/settings");
</script>

<template><main>{{ settings }}</main></template>

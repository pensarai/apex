<script setup lang="ts">
const audit = await $fetch("/api/admin/audit-log");
</script>

<template><main>{{ audit }}</main></template>

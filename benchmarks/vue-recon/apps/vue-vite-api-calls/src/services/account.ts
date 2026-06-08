import axios from "axios";

const apiBase = import.meta.env.VITE_API_URL || "/api";

const client = axios.create({
  baseURL: apiBase,
  headers: { "x-client": "vue-recon-fixture" },
});

export async function loadAccount() {
  return client.get("/account");
}

export async function loadFeatureFlags() {
  return fetch(`${apiBase}/feature-flags`).then((res) => res.json());
}

export async function searchAccounts(query: string) {
  return fetch(`/api/search?q=${encodeURIComponent(query)}`);
}

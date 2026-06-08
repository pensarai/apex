export async function loadSession() {
  return fetch("/api/session").then((res) => res.json());
}

export async function listProjects() {
  return fetch("/api/projects").then((res) => res.json());
}

export async function loadProject(projectId: string) {
  return fetch(`/api/projects/${projectId}`).then((res) => res.json());
}

export async function loadMonthlyReport() {
  return fetch("/api/reports/monthly").then((res) => res.json());
}

export type EvidenceSource = "observed" | "source" | "cloud" | "inferred";

export interface Evidence {
  source: EvidenceSource;
  detail: string;
  ref?: string;
}

export type BoundaryKind =
  | "edge-network"
  | "cloud-account"
  | "region"
  | "vpc"
  | "subnet"
  | "third-party"
  | "user-device"
  | "unplaced";

export type ControlKind =
  | "waf"
  | "ip-allowlist"
  | "geo-block"
  | "security-group"
  | "network-isolation"
  | "origin-secret"
  | "authentication"
  | "authorization"
  | "tenant-isolation"
  | "rate-limit"
  | "encryption"
  | "secret-management"
  | "iam-policy"
  | "input-validation"
  | "logging";

export interface Control {
  id: string;
  name: string;
  kind: ControlKind;
  appliesTo: string[];
  protects: string;
  gaps?: string;
  evidence: Evidence[];
}

export interface Boundary {
  id: string;
  name: string;
  kind: BoundaryKind;
  provider?: string;
  parent?: string;
  description?: string;
  evidence: Evidence[];
}

export type ComponentKind =
  | "application"
  | "client"
  | "entrypoint"
  | "compute"
  | "database"
  | "cache"
  | "queue"
  | "object-store"
  | "message-broker"
  | "proxy"
  | "identity-provider"
  | "llm-provider"
  | "saas";

export type Exposure = "public" | "private" | "unknown";

export interface Component {
  id: string;
  recordId?: string;
  name: string;
  kind: ComponentKind;
  boundary: string;
  tech?: string;
  exposure: Exposure;
  endpoints?: string[];
  usedBy: string[];
  repository?: string;
  description?: string;
  atStake: string;
  trustAssumptions: string[];
  businessLogic?: string;
  members?: string[];
  evidence: Evidence[];
}

export type ThreatCategory =
  | "spoofing"
  | "tampering"
  | "repudiation"
  | "information-disclosure"
  | "denial-of-service"
  | "elevation-of-privilege";

export interface Threat {
  id: string;
  component: string;
  title: string;
  category: ThreatCategory;
  entryPoint?: string;
  scenario: string;
  attackSteps: string[];
  preconditions: string[];
  impact: string;
  severity?: "critical" | "high" | "medium" | "low";
  likelihood: "low" | "medium" | "high";
  likelihoodRationale: string;
  controls: string[];
  verification?: string;
  evidence: Evidence[];
}

export interface Flow {
  id?: string;
  from: string;
  to: string;
  label: string;
  evidence: Evidence[];
}

export interface Topology {
  name: string;
  description: string;
  origin: string;
  boundaries: Boundary[];
  components: Component[];
  flows: Flow[];
  controls: Control[];
  threats: Threat[];
}

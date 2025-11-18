// Types for the Braintrust core system

// Configuration interface for Braintrust integration
export interface BraintrustConfig {
    apiKey: string;
    projectName?: string;
    enabled: boolean;
    clientId?: string;
    environment?: 'dev' | 'staging' | 'prod';
}

// Metadata interface for agent spans in Braintrust
export interface AgentSpanMetadata {
    agent_type: 'thoroughPentest' | 'pentest' | 'attackSurface' | 'documentFinding'; // Types of agent currently implemented
    session_id: string;
}
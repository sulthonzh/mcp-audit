export interface SecurityIssue {
  type: 'high' | 'medium' | 'low';
  category: 'permissions' | 'config' | 'filesystem' | 'network' | 'injection' | 'supply-chain' | 'transport';
  title: string;
  description: string;
  recommendation: string;
  evidence?: string;
}

export interface ScanSummary {
  configFilesFound: number;
  highRiskIssues: number;
  mediumRiskIssues: number;
  lowRiskIssues: number;
}

export interface SecurityResult {
  scanType: 'config' | 'server';
  timestamp: string;
  target: string;
  issues: SecurityIssue[];
  score: number;
  summary: ScanSummary;
  metadata?: Record<string, unknown>;
}

export interface VulnerabilityDatabaseEntry {
  id: string;
  title: string;
  description: string;
  severity: 'high' | 'medium' | 'low';
  affectedPackages: string[];
  patchedVersions: string[];
  published: string;
  updated: string;
  references?: string[];
}
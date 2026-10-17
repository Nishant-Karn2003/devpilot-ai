export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';
export type Finding = {
  id: string;
  file_path: string | null;
  line: number | null;
  column: number | null;
  end_line: number | null;
  end_column: number | null;
  rule_id: string;
  analyzer: string;
  severity: Severity;
  category: string;
  title: string;
  description: string;
  evidence: string | null;
  remediation: string | null;
  origin: string;
};
export type Analysis = {
  id: string;
  status: 'queued' | 'running' | 'completed' | 'failed';
  language: string;
  source_name: string;
  mode: string;
  gate_threshold: string;
  summary: Record<string, unknown>;
  quality_gate: { passed?: boolean; threshold?: string; reasons?: string[]; note?: string };
  error_message: string | null;
  created_at: string;
  completed_at: string | null;
  findings: Finding[];
  patch_suggestions: PatchSuggestion[];
};
export type PatchSuggestion = {
  id: string;
  analysis_id: string;
  finding_id: string;
  patch: string;
  explanation: string;
  status: 'pending' | 'accepted' | 'rejected';
  created_at: string;
  reviewed_at: string | null;
};
export type Dependency = {
  name: string;
  declared_spec: string;
  resolved_version: string | null;
  direct: boolean;
  ecosystem: string;
};
export type Vulnerability = {
  package_name: string;
  resolved_version: string;
  id: string;
  aliases: string[];
  summary: string;
  severity: string;
  modified: string | null;
  references: string[];
};
export type DependencyScan = {
  id: string;
  ecosystem: string;
  status: string;
  inventory: Dependency[];
  vulnerabilities: Vulnerability[];
  warnings: string[];
  error_message: string | null;
  created_at: string;
  completed_at: string | null;
};
export type Overview = {
  analysis_count: number;
  severity_distribution: Record<string, number>;
  recent_analyses: Array<{
    id: string; status: string; language: string; source_name: string; created_at: string; findings: number;
  }>;
  snapshot_note: string;
};

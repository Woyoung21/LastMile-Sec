/** Types aligned with pipeline remediated JSON packets under `data/remediated/`. */

export type Severity = "critical" | "high" | "medium" | "low" | "info" | string;

export interface AffectedAsset {
  identifier: string;
  asset_type: string;
  details: string | null;
}

export interface MitreMapping {
  mitre_ids: string[];
  validation_passed?: boolean;
  routing_mode?: string;
  mapping_agent?: string;
  db_context?: string;
  framework?: string;
  retrieved_examples?: number;
  raw_model_output?: string;
  mapped_at?: string;
  timing_ms?: Record<string, number>;
}

export interface RemediationStep {
  step_number?: number;
  title?: string;
  command_or_action?: string;
  explanation?: string;
  vendor_product?: string;
  step_type?: string;
  ui_breadcrumb?: string | null;
  substeps?: string[];
  evidence_tier?: string;
  supporting_urls?: string[];
}

export interface SelfragIssue {
  check: string;
  severity: string;
  message: string;
}

export interface SelfragVerification {
  grounding_score?: number;
  relevance_score?: number;
  completeness_score?: number;
  substep_quality_score?: number;
  passed: boolean;
  issues: SelfragIssue[];
  attempts?: number;
}

export interface RemediationBlock {
  executive_summary: string;
  limitations?: string[];
  steps: RemediationStep[];
  priority?: string;
  estimated_effort?: string;
  prerequisites?: string[];
  verification_procedure?: string;
  source_control_ids?: string[];
  provenance?: Record<string, unknown>;
  model?: string;
  prompt_version?: string;
  generated_at?: string;
  selfrag_verification?: SelfragVerification;
}

export interface FindingMetadata {
  ports?: string[];
  services?: string[];
  hostnames?: string[];
  extracted_by_parser_version?: string;
  technical_summary?: string;
  summary_source?: string;
  summary_generated_at?: string;
  summary_prompt_version?: string;
  summary_model?: string;
  mitre_mapping?: MitreMapping;
  rag_correlation?: Record<string, unknown>;
  remediation?: RemediationBlock;
  [key: string]: unknown;
}

export interface Finding {
  id: string;
  severity: Severity;
  title: string;
  description: string;
  affected_assets: AffectedAsset[];
  raw_excerpt?: string;
  cve_ids?: string[];
  cvss_score?: number | null;
  recommendations?: string[];
  references?: string[];
  source_ip?: string | null;
  destination_ip?: string | null;
  protocol?: string | null;
  timestamp_observed?: string | null;
  metadata?: FindingMetadata;
}

export interface RemediatedPacket {
  id: string;
  source_type?: string;
  source_file?: string;
  source_hash?: string;
  timestamp?: string;
  report_date?: string | null;
  findings: Finding[];
  [key: string]: unknown;
}

export interface LatestApiResponse {
  filename: string;
  path: string;
  data: RemediatedPacket;
}

export interface InventoryResponse {
  folder: string;
  path: string;
  files: string[];
  exists: boolean;
}

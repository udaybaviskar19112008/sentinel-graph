import type { Subsystem, ThreatAssessment, VerdictLevel } from '@/store/useThreatStore'

/**
 * The fusion model's 12 features, in src/fusion/meta_scorer.py FEATURES order (change both
 * together). `summary` is the one-line tooltip; `detail` the full explanation, which says
 * plainly when a feature is inverted, unused, or a stand-in.
 */
export const FEATURE_SPACE = [
  {
    name: 'auth_fail_count',
    label: 'Authentication failures',
    subsystem: 'PROTOCOL_FORENSICS',
    summary: 'How many of SPF, DKIM, DMARC and ARC failed.',
    detail:
      'Counts SPF, DKIM, DMARC and ARC results of "fail" in the trusted Authentication-Results header (0–4). Both training corpora predate Authentication-Results headers, so it was constant in training and the deployed model cannot use it yet.',
  },
  {
    name: 'display_name_spoof_risk',
    label: 'Display-name spoofing',
    subsystem: 'PROTOCOL_FORENSICS',
    summary: 'A protected brand named by a sender who does not own it.',
    detail:
      '1.0 when the display name names a protected brand the sending domain does not own; 0.5 when the brand appears only in the subject. Matched after homoglyph, zero-width and leetspeak folding.',
  },
  {
    name: 'private_ip_leak',
    label: 'Private hop in route',
    subsystem: 'PROTOCOL_FORENSICS',
    summary: 'A private address between public relays.',
    detail:
      'A private (RFC 1918 / loopback) address sits between public relays on the sender side. Known weakness: the model learned it backwards — two-thirds of the legitimate training mail is mailing-list traffic through private corporate relays, so it usually lowers risk.',
  },
  {
    name: 'timestamp_regression',
    label: 'Clock regression',
    subsystem: 'PROTOCOL_FORENSICS',
    summary: 'A later relay stamped the mail earlier than a previous one.',
    detail:
      'A later hop is timestamped before an earlier one (beyond 60 s of clock skew) — a sign of injected or forged Received headers.',
  },
  {
    name: 'screenshot_hash_exists',
    label: 'Lure rendered',
    subsystem: 'VISION_ENGINE',
    summary: 'The sandbox rendered the first link.',
    detail:
      'Whether the sandbox captured a screenshot of the first link. Nothing is detonated during offline training, so it was constant and the deployed model cannot use it.',
  },
  {
    name: 'visual_spoof_score',
    label: 'Visual brand similarity',
    subsystem: 'VISION_ENGINE',
    summary: 'How closely the rendered page imitates a protected brand.',
    detail:
      'Visual similarity of the rendered page to a protected brand. The vision model is an untrained stand-in, so this carries no signal yet.',
  },
  {
    name: 'is_cred_harvester',
    label: 'Credential harvester',
    subsystem: 'VISION_ENGINE',
    summary: 'The rendered page collects credentials.',
    detail: 'Whether the rendered page asks for credentials or payment data. Stand-in vision model: not yet detected.',
  },
  {
    name: 'graph_nodes_count',
    label: 'Delivery-graph size',
    subsystem: 'TOPOLOGY_GNN',
    summary: 'Sender + relay hops + receiver + links.',
    detail:
      'Nodes in the delivery graph: the sender, each relay hop, the receiver and each link. The ablation shows this, not the MemAE loss, carries the topology signal (removing both: AUC 0.953 → 0.936).',
  },
  {
    name: 'memae_loss',
    label: 'MemAE route anomaly',
    subsystem: 'TOPOLOGY_GNN',
    summary: 'How unusual the delivery route looks to the graph autoencoder.',
    detail:
      'Reconstruction loss of the delivery graph under the memory-augmented autoencoder: high means unlike any route it learned from legitimate mail; above the calibrated threshold, the route is flagged zero-day. Its nodes only know their position, so it sees route shape, and in the ablation removing it left the AUC unchanged (0.953).',
  },
  {
    name: 'slm_verdict_severity',
    label: 'Language-model verdict',
    subsystem: 'COGNITIVE_SLM',
    summary: 'The reasoning model’s verdict as a rank (0–3).',
    detail:
      'The language model’s verdict as a rank: BENIGN 0, SUSPICIOUS 1, PHISHING 2, CRITICAL 3. Held constant in training (mapping labels into it would leak the answer), so it carries no weight; the current model is also a stand-in that always says CRITICAL.',
  },
  {
    name: 'dga_max_entropy',
    label: 'DGA entropy',
    subsystem: 'CONTENT_HEURISTICS',
    summary: 'Randomness of the most random link domain, in bits.',
    detail:
      'Shannon entropy of the most random link’s registrable label — the part left of the public suffix. Legitimate links cluster at 2.5–3.0 bits; phishing fills both tails. In the ablation it is the stronger content feature (removing it: AUC 0.953 → 0.935).',
  },
  {
    name: 'nlp_urgency_score',
    label: 'NLP coercion',
    subsystem: 'CONTENT_HEURISTICS',
    summary: 'Coercive phrases in the body: 0.25 each, capped at 1.',
    detail:
      'Coercive phrases such as “account suspended”, “verify your identity” and “final notice”, matched in their natural inflections after zero-width characters are removed: 0.25 per phrase, capped at 1. Fires on 20.3% of training phishing and 0.1% of legitimate mail.',
  },
] as const satisfies readonly { name: string; label: string; subsystem: Subsystem; summary: string; detail: string }[]

export type FeatureName = (typeof FEATURE_SPACE)[number]['name']
export type FeatureInfo = (typeof FEATURE_SPACE)[number]

const VERDICT_RANK: Record<VerdictLevel, number> = { BENIGN: 0, SUSPICIOUS: 1, PHISHING: 2, CRITICAL: 3 }

/** The row the fusion model scored, rebuilt as meta_scorer._build_feature_vector builds it. */
export function featureValues(assessment: ThreatAssessment, verdict: VerdictLevel): Record<FeatureName, number> {
  const header = assessment.header_forensics
  const vision = assessment.vision_forensics
  const topology = assessment.topology_forensics
  return {
    auth_fail_count: (['spf', 'dkim', 'dmarc', 'arc'] as const).filter((method) => header[method] === 'fail').length,
    display_name_spoof_risk: header.display_name_spoof_risk,
    private_ip_leak: header.private_ip_leak ? 1 : 0,
    timestamp_regression: header.timestamp_regression_flag ? 1 : 0,
    screenshot_hash_exists: vision?.screenshot_hash ? 1 : 0,
    visual_spoof_score: vision?.visual_spoof_score ?? 0,
    is_cred_harvester: vision?.is_credential_harvester ? 1 : 0,
    graph_nodes_count: topology?.graph_nodes_count ?? 0,
    memae_loss: topology?.memae_reconstruction_loss ?? 0,
    slm_verdict_severity: VERDICT_RANK[verdict],
    dga_max_entropy: header.dga_max_entropy,
    nlp_urgency_score: header.nlp_urgency_score,
  }
}

const YES_NO = new Set<FeatureName>(['private_ip_leak', 'timestamp_regression', 'screenshot_hash_exists', 'is_cred_harvester'])
const VERDICT_NAME = ['BENIGN', 'SUSPICIOUS', 'PHISHING', 'CRITICAL'] as const

/** A feature value as an analyst reads it. */
export function formatFeature(name: FeatureName, value: number): string {
  if (YES_NO.has(name)) return value ? 'yes' : 'no'
  switch (name) {
    case 'auth_fail_count':
      return `${value} of 4`
    case 'graph_nodes_count':
      return `${value} nodes`
    case 'slm_verdict_severity':
      return `${value} (${VERDICT_NAME[value] ?? '?'})`
    case 'dga_max_entropy':
      return value > 0 ? `${value.toFixed(2)} bits` : 'no link'
    case 'memae_loss':
      return value.toFixed(3)
    default:
      return value.toFixed(2)
  }
}

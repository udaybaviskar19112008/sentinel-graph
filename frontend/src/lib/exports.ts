import { FEATURE_SPACE, featureValues } from '@/lib/featureSpace'
import type { Scan } from '@/lib/historyApi'
import type { AnalysisDetails, ThreatAssessment } from '@/store/useThreatStore'

export type CsvCell = string | number | boolean | null | undefined

// A spreadsheet runs a text cell that starts with one of these as a formula (CSV injection).
const FORMULA_TRIGGERS = /^[=+\-@\t\r]/

/**
 * One RFC 4180 field. Text is attacker-controlled here (subjects, senders, URLs), so a cell
 * that would start a formula gets a leading apostrophe (OWASP's mitigation): opening the
 * file in Excel or Sheets shows the text instead of running it. Numbers are written as-is.
 */
export function csvCell(value: CsvCell): string {
  if (value === null || value === undefined) return ''
  if (typeof value === 'number') return Number.isFinite(value) ? String(value) : ''
  if (typeof value === 'boolean') return value ? 'true' : 'false'
  const text = FORMULA_TRIGGERS.test(value) ? `'${value}` : value
  return /[",\r\n]/.test(text) ? `"${text.replaceAll('"', '""')}"` : text
}

export function toCsv(rows: CsvCell[][]): string {
  return rows.map((row) => row.map(csvCell).join(',')).join('\r\n') + '\r\n'
}

/** Hand `content` to the browser as a download named `filename`. */
export function downloadText(content: string, filename: string, type: string): void {
  const url = URL.createObjectURL(new Blob([content], { type }))
  const link = document.createElement('a')
  link.href = url
  link.download = filename
  document.body.append(link)
  link.click()
  link.remove()
  setTimeout(() => URL.revokeObjectURL(url), 0) // after the click has handed the blob over
}

/** The full machine-readable report for one assessment, caveats included. */
export function assessmentReport(assessment: ThreatAssessment, details: AnalysisDetails, generatedAt = new Date()) {
  const status = details.modelStatus
  const caveats = [
    status.slm_dummy && 'The language model is a scripted stand-in: its verdict (and analyst_trace) are not evidence.',
    status.vision_placeholder && 'The vision model is an untrained stand-in: visual scores carry no meaning.',
    status.memae_placeholder && 'The MemAE is an untrained stand-in: route anomaly losses carry no meaning.',
    status.fusion_dummy && 'The fusion model is a synthetic placeholder: the risk score carries no meaning.',
    !status.zero_day_calibrated && 'No calibrated zero-day threshold: is_zero_day_route is never set.',
  ].filter((note): note is string => typeof note === 'string')
  return {
    format: 'sentinel-graph-report/1',
    generated_at: generatedAt.toISOString(),
    scan_id: details.scanId,
    analysis_id: details.analysisId,
    overall_risk: assessment.overall_risk,
    risk_probability: details.riskProbability,
    verdict: details.verdict,
    caveats,
    model_status: status,
    features: featureValues(assessment, details.verdict),
    shap_contributions: details.contributions,
    assessment,
  }
}

/** One row: the 12 feature values the model scored, plus the risk. */
export function metricsCsv(assessment: ThreatAssessment, details: AnalysisDetails): string {
  const values = featureValues(assessment, details.verdict)
  const names = FEATURE_SPACE.map((feature) => feature.name)
  return toCsv([
    ['scan_id', 'subject', ...names, 'overall_risk', 'risk_probability', 'verdict'],
    [
      details.scanId,
      assessment.header_forensics.subject,
      ...names.map((name) => values[name]),
      assessment.overall_risk,
      details.riskProbability,
      details.verdict,
    ],
  ])
}

/** One row per saved scan, newest first. */
export function historyCsv(scans: Scan[]): string {
  return toCsv([
    ['scan_id', 'timestamp', 'subject', 'sender', 'verdict', 'overall_risk', 'indicators', 'malicious_indicators'],
    ...scans.map((scan) => [
      scan.id,
      scan.timestamp,
      scan.subject,
      scan.sender,
      scan.final_verdict,
      scan.overall_risk,
      scan.indicators.map((indicator) => `${indicator.type}:${indicator.value}`).join('; '),
      scan.indicators.filter((indicator) => indicator.malicious_flag).length,
    ]),
  ])
}

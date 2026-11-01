import type { ModelStatus } from '@/store/useThreatStore'

/** The fusion classifier's own decision threshold: probability 0.5, risk 50. */
export const DECISION_LINE = 50

/** Engines answering with untrained stand-ins, whose scores are not evidence. */
export function standIns(status: ModelStatus): string[] {
  return [
    status.vision_placeholder && 'vision',
    status.memae_placeholder && 'MemAE',
    !status.zero_day_calibrated && 'zero-day threshold',
    status.fusion_dummy && 'fusion',
    status.slm_dummy && 'SLM',
  ].filter((name): name is string => typeof name === 'string')
}

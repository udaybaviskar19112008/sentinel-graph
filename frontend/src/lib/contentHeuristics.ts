/** Constants of the two content heuristics, shared by the live card and the ML forensics page. */

export const POINTS_PER_PHRASE = 0.25 // nlp_heuristics.POINTS_PER_MATCH: one coercive phrase
export const DGA_SCALE_MAX_BITS = 5 // a registrable label rarely exceeds ~5 bits (log2 of its character set)
// Where most legitimate links sit. Research corpus (2002-06): 52% of legitimate links fall in
// 2.5-3.0 bits against 23% of phishing, which spreads into both tails. So DGA entropy is not
// "higher is worse" (low-entropy labels are phishing-heavy too), and its scale carries no risk colour.
export const LEGITIMATE_BAND_BITS: readonly [number, number] = [2.5, 3.0]

// The eight phrase families nlp_heuristics.py matches, each also in its natural inflections.
export const COERCIVE_PHRASES = [
  'immediate action',
  'account suspended',
  'verify your identity',
  'invoice attached',
  'password expires',
  'unauthorised access',
  'final notice',
  'click here to cancel',
] as const

export function phraseCount(score: number): number {
  return Math.round(score / POINTS_PER_PHRASE)
}

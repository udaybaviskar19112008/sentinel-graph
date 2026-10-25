import { clsx, type ClassValue } from 'clsx'
import { twMerge } from 'tailwind-merge'

/** Join class names conditionally; later Tailwind classes win conflicts (`p-2` then `p-4` -> `p-4`). */
export function cn(...inputs: ClassValue[]): string {
  return twMerge(clsx(inputs))
}

// Semantic tone helpers — turn business state into a color intent in ONE place
// so pages stop scattering `status === 'active' ? 'green' : 'red'` ternaries.
// A tone maps to alpha-token classes that adapt to light/dark automatically.
import type { ReactNode } from 'react'
import { cn } from '@mxid/shared'

export type StatusTone = 'success' | 'warning' | 'danger' | 'info' | 'neutral' | 'primary'

const TONE_CLASS: Record<StatusTone, string> = {
  success: 'bg-success/10 text-success',
  warning: 'bg-warning/10 text-warning',
  danger: 'bg-danger/10 text-danger',
  info: 'bg-info/10 text-info',
  primary: 'bg-primary/10 text-primary',
  neutral: 'bg-muted/10 text-muted',
}

const PILL = 'inline-flex items-center whitespace-nowrap rounded-full px-2 py-0.5 text-xs font-medium'

// StatusTag — the generic status pill. `dot` adds a leading indicator dot.
export function StatusTag({
  tone = 'neutral',
  dot,
  children,
}: {
  tone?: StatusTone
  dot?: boolean
  children: ReactNode
}) {
  return (
    <span className={cn(PILL, TONE_CLASS[tone])}>
      {dot && <span className="mr-1 h-1.5 w-1.5 rounded-full bg-current" />}
      {children}
    </span>
  )
}

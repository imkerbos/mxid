import { useEffect, useRef, useState } from 'react'
import { setStepUpHandler, useTranslation } from '@mxid/shared'
import { Modal } from '@mxid/shared/ui'
import StepUpPrompt from './StepUpPrompt'

/**
 * StepUpModal owns the portal's global step-up flow, mirroring the console's.
 * On mount it registers the handler the API client invokes whenever a request
 * comes back step_up_required (40330, or form-fill's 40133): the handler opens
 * this modal and resolves once the challenge passes, at which point the client
 * transparently replays the original request.
 *
 * The portal needs its own because the sudo window is per session namespace —
 * verifying in the console does nothing for a portal-side gate.
 */
export default function StepUpModal() {
  const { t } = useTranslation()
  const [open, setOpen] = useState(false)
  const pending = useRef<{ resolve: () => void; reject: () => void } | null>(null)

  useEffect(() => {
    setStepUpHandler(
      () =>
        new Promise<void>((resolve, reject) => {
          pending.current = { resolve, reject }
          setOpen(true)
        }),
    )
    return () => setStepUpHandler(null)
  }, [])

  // settle resolves (ok) or rejects (cancel) the pending client promise so the
  // interceptor either replays the original request or surfaces the refusal.
  const settle = (ok: boolean) => {
    setOpen(false)
    const p = pending.current
    pending.current = null
    if (!p) return
    if (ok) p.resolve()
    else p.reject()
  }

  return (
    <Modal open={open} title={t('stepup.title')} onClose={() => settle(false)} size="sm" elevated>
      <StepUpPrompt onVerified={() => settle(true)} onCancel={() => settle(false)} />
    </Modal>
  )
}

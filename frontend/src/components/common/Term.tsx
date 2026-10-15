import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip'

/** Inline technical term with a plain-language tooltip (keyboard focusable). */
export function Term({ children, hint }: { children: React.ReactNode; hint: string }) {
  return (
    <Tooltip>
      <TooltipTrigger
        render={
          <span
            tabIndex={0}
            className="cursor-help rounded-sm underline decoration-dotted decoration-muted-foreground/60 underline-offset-4 outline-none focus-visible:ring-2 focus-visible:ring-cyan/50"
          />
        }
      >
        {children}
      </TooltipTrigger>
      <TooltipContent className="max-w-64 text-xs leading-relaxed">{hint}</TooltipContent>
    </Tooltip>
  )
}

export const TERMS = {
  risk: 'A VEYLIX prioritisation score for triage. It is not a calibrated probability and does not mean data was stolen.',
  baseline: "The device's typical recent behaviour (volume, connections, destinations) that new activity is compared against.",
  anomaly: 'Behaviour that differs from the baseline. An anomaly is a reason to investigate, not proof of wrongdoing.',
  signals: 'The individual behaviours the detector flagged, such as unusual volume, a new destination or a connection burst.',
  metadata: 'Connection facts only (destination, size, timing). Encrypted payloads are never decrypted or read.',
  burst: 'Many connections in a short window, which can differ from the device’s normal pattern.',
} as const

import { useEffect, useRef, useState } from 'react'

const EMPTY: ReadonlySet<string> = new Set()
const HIGHLIGHT_MS = 1600

/**
 * Returns the ids that arrived *after* the first loaded snapshot, for a short highlight window.
 * - The first non-undefined snapshot is the baseline: nothing in it is highlighted.
 * - Pass the full source id list (not the sorted/filtered/paged rows) so re-ordering never counts as "new".
 * - Nothing is ever generated: it only reacts to ids genuinely returned by the backend.
 */
export function useNewRowIds(ids: string[] | undefined): ReadonlySet<string> {
  const seen = useRef<Set<string> | null>(null)
  const timers = useRef<number[]>([])
  const [fresh, setFresh] = useState<ReadonlySet<string>>(EMPTY)

  useEffect(() => {
    if (!ids) return
    if (seen.current === null) {
      seen.current = new Set(ids)
      return
    }
    const known = seen.current
    const added = ids.filter((id) => !known.has(id))
    if (added.length === 0) return
    added.forEach((id) => known.add(id))
    setFresh((prev) => new Set([...prev, ...added]))
    const t = window.setTimeout(() => {
      setFresh((prev) => {
        const next = new Set(prev)
        added.forEach((id) => next.delete(id))
        return next
      })
    }, HIGHLIGHT_MS)
    timers.current.push(t)
  }, [ids])

  useEffect(() => {
    const pending = timers.current
    return () => pending.forEach((t) => window.clearTimeout(t))
  }, [])

  return fresh
}

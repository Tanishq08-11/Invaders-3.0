/** Static light azure backdrop for the public pages: soft glows and a faint grid. No WebGL, no animation. */
export function OverviewBackground({ height = 420 }: { height?: number | string }) {
  return (
    <div
      aria-hidden
      className="pointer-events-none absolute inset-x-0 top-0 -z-0 overflow-hidden"
      style={{ height, maskImage: 'linear-gradient(to bottom, black 70%, transparent 100%)', WebkitMaskImage: 'linear-gradient(to bottom, black 70%, transparent 100%)' }}
    >
      <div className="absolute inset-0 bg-[radial-gradient(60%_70%_at_50%_0%,rgba(0,120,212,0.14),transparent),radial-gradient(40%_50%_at_90%_30%,rgba(37,99,235,0.10),transparent)]" />
      <div className="absolute inset-0 bg-[linear-gradient(to_right,rgba(0,120,212,0.06)_1px,transparent_1px),linear-gradient(to_bottom,rgba(0,120,212,0.06)_1px,transparent_1px)] bg-[size:44px_44px] [mask-image:radial-gradient(ellipse_70%_70%_at_50%_30%,black,transparent_85%)]" />
    </div>
  )
}

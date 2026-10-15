/** Static light ambient layers shared by the portals: soft azure corner glows plus a very faint grid. No animation. */
export function PortalBackground() {
  return (
    <>
      <div
        aria-hidden
        className="pointer-events-none fixed inset-0 z-0 bg-[radial-gradient(55%_45%_at_0%_0%,rgba(0,120,212,0.10),transparent_70%),radial-gradient(45%_40%_at_100%_0%,rgba(37,99,235,0.08),transparent_70%),radial-gradient(60%_40%_at_50%_100%,rgba(0,120,212,0.06),transparent_70%)]"
      />
      <div
        aria-hidden
        className="pointer-events-none fixed inset-0 z-0 bg-[linear-gradient(to_right,rgba(0,120,212,0.05)_1px,transparent_1px),linear-gradient(to_bottom,rgba(0,120,212,0.05)_1px,transparent_1px)] bg-[size:44px_44px] [mask-image:radial-gradient(ellipse_80%_70%_at_50%_30%,black,transparent_85%)]"
      />
    </>
  )
}

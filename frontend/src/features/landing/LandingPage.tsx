import { Link } from 'react-router-dom'
import { motion, MotionConfig } from 'motion/react'
import {
  ArrowRight,
  Binary,
  Eye,
  EyeOff,
  FileLock2,
  FolderLock,
  Fingerprint,
  Gauge,
  LayoutDashboard,
  MonitorSmartphone,
  Network,
  ScanSearch,
  ShieldCheck,
  Siren,
  Workflow,
} from 'lucide-react'
import StrokeText from '@/components/StrokeText'
import DecryptedText from '@/components/DecryptedText'
import SpotlightCard from '@/components/SpotlightCard'
import { OverviewBackground } from '@/components/effects/OverviewBackground'
import { buttonVariants } from '@/components/ui/button'
import { routes } from '@/lib/routes'
import { cn } from '@/lib/utils'

const NAV = [
  { href: '#how-it-works', label: 'How it works' },
  { href: '#capabilities', label: 'Capabilities' },
  { href: '#experience', label: 'Experience' },
  { href: '#privacy', label: 'Privacy' },
]

const reveal = {
  initial: { opacity: 0, y: 24 },
  whileInView: { opacity: 1, y: 0 },
  viewport: { once: true, margin: '-80px' },
  transition: { duration: 0.6, ease: 'easeOut' as const },
}

function Eyebrow({ children }: { children: React.ReactNode }) {
  return <p className="mb-3 text-xs font-medium uppercase tracking-[0.2em] text-cyan">{children}</p>
}

function SectionHeading({ eyebrow, title, children }: { eyebrow: string; title: string; children?: React.ReactNode }) {
  return (
    <motion.div {...reveal} className="mx-auto mb-12 max-w-2xl text-center">
      <Eyebrow>{eyebrow}</Eyebrow>
      <h2 className="text-3xl font-semibold tracking-tight sm:text-4xl">{title}</h2>
      {children && <p className="mt-4 text-base leading-relaxed text-muted-foreground">{children}</p>}
    </motion.div>
  )
}

function Header() {
  return (
    <header className="sticky top-0 z-40 border-b border-border/60 bg-background/70 backdrop-blur">
      <div className="mx-auto flex h-16 max-w-6xl items-center gap-6 px-4 sm:px-6">
        <Link to="/" className="flex items-center gap-2 font-semibold tracking-[0.2em]">
          <ShieldCheck className="size-5 text-cyan" />
          VEYLIX
        </Link>
        <nav aria-label="Sections" className="ml-4 hidden gap-6 text-sm text-muted-foreground md:flex">
          {NAV.map((n) => (
            <a key={n.href} href={n.href} className="transition-colors hover:text-foreground">
              {n.label}
            </a>
          ))}
        </nav>
        <Link to={routes.login} className={cn(buttonVariants({ size: 'sm' }), 'ml-auto')}>
          Sign in
        </Link>
      </div>
    </header>
  )
}

function Hero() {
  return (
    <section className="relative isolate flex min-h-[calc(100vh-4rem)] items-center overflow-hidden">
      <OverviewBackground height="100%" />
      <div className="relative z-10 mx-auto flex w-full max-w-4xl flex-col items-center px-4 py-20 text-center sm:px-6">
        <motion.p
          initial={{ opacity: 0, y: 8 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.5 }}
          className="mb-6 inline-flex items-center gap-2 rounded-full border border-cyan/30 bg-cyan/10 px-3 py-1 text-xs text-cyan"
        >
          <EyeOff className="size-3.5" /> Metadata-only detection. Payloads stay encrypted.
        </motion.p>

        <h1 className="w-full max-w-2xl">
          <StrokeText
            text="VEYLIX"
            strokeColor="#0078D4"
            fillColor="#102A43"
            strokeWidth={1.6}
            drawDuration={1.4}
            fillDelay={0.15}
            stagger={0.09}
            ease="power2.out"
            trigger="mount"
            fillMode="wipe"
            fontSize={150}
            fontWeight={800}
            letterSpacing={10}
          />
        </h1>

        <p className="mt-6 text-2xl font-medium tracking-tight sm:text-3xl">
          <DecryptedText
            text="See the Threat. Never the Data."
            animateOn="view"
            sequential
            speed={35}
            maxIterations={14}
            revealDirection="start"
            encryptedClassName="text-cyan/70"
          />
        </p>

        <motion.p
          initial={{ opacity: 0, y: 12 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.6, delay: 0.5 }}
          className="mt-5 max-w-xl text-base leading-relaxed text-muted-foreground"
        >
          AI-powered detection of suspicious encrypted network activity — without decrypting sensitive communications.
        </motion.p>

        <motion.div
          initial={{ opacity: 0, y: 12 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.6, delay: 0.65 }}
          className="mt-9 flex flex-wrap items-center justify-center gap-3"
        >
          <Link to={routes.login} className={cn(buttonVariants({ size: 'lg' }), 'shadow-[0_0_30px_-6px_var(--accent-cyan)]')}>
            Get Started <ArrowRight className="size-4" />
          </Link>
          <a href="#how-it-works" className={buttonVariants({ size: 'lg', variant: 'outline' })}>
            Explore Technology
          </a>
        </motion.div>
      </div>
    </section>
  )
}

function Problem() {
  const points = [
    { icon: FileLock2, title: 'Encryption protects communication', text: 'HTTPS/TLS keeps legitimate traffic confidential - exactly as it should.' },
    { icon: EyeOff, title: 'Content inspection hits a wall', text: 'Traditional tools that read payloads cannot see inside encrypted connections.' },
    { icon: Network, title: 'Behavior is still observable', text: 'Volume, timing, duration and destinations remain visible - and can reveal unusual outbound transfers.' },
  ]
  return (
    <section className="mx-auto max-w-6xl px-4 py-24 sm:px-6">
      <SectionHeading eyebrow="The problem" title="Encrypted Traffic. Hidden Threats.">
        Encryption is not the weakness. But a trusted insider can move data out over the same protected channels everyone relies on, and
        content-based tools cannot tell the difference.
      </SectionHeading>
      <div className="grid gap-4 md:grid-cols-3">
        {points.map((p, i) => (
          <motion.div key={p.title} {...reveal} transition={{ ...reveal.transition, delay: i * 0.1 }} className="rounded-xl border border-border bg-surface p-6">
            <p.icon className="mb-4 size-6 text-cyan" />
            <h3 className="font-semibold">{p.title}</h3>
            <p className="mt-2 text-sm leading-relaxed text-muted-foreground">{p.text}</p>
          </motion.div>
        ))}
      </div>
    </section>
  )
}

function HowItWorks() {
  const steps = [
    { n: '01', icon: ScanSearch, title: 'Observe', text: 'Collect observable network-flow metadata without decrypting payloads.', chips: ['Volume', 'Timing', 'Duration', 'Destinations'] },
    { n: '02', icon: Binary, title: 'Analyze', text: 'Use AI-based anomaly detection to identify unusual traffic patterns.', chips: ['Baselines', 'Anomaly score', 'Risk signals'] },
    { n: '03', icon: Siren, title: 'Investigate', text: 'Present risk indicators, supporting evidence and incident timelines to security analysts.', chips: ['Evidence', 'Timeline', 'Status'] },
  ]
  return (
    <section id="how-it-works" className="border-y border-border bg-surface/40 py-24">
      <div className="mx-auto max-w-6xl px-4 sm:px-6">
        <SectionHeading eyebrow="How VEYLIX works" title="From raw flows to explainable alerts" />
        <ol className="relative grid gap-6 md:grid-cols-3">
          {/* animated connector behind the cards (desktop) */}
          <svg aria-hidden className="pointer-events-none absolute left-0 top-1/2 hidden h-2 w-full -translate-y-1/2 md:block" preserveAspectRatio="none" viewBox="0 0 100 2">
            <motion.line
              x1="8" y1="1" x2="92" y2="1"
              stroke="#0078D4" strokeOpacity="0.5" strokeWidth="0.4" strokeDasharray="1.2 1.2" vectorEffect="non-scaling-stroke"
              initial={{ pathLength: 0 }}
              whileInView={{ pathLength: 1 }}
              viewport={{ once: true }}
              transition={{ duration: 1.4, ease: 'easeInOut' }}
            />
          </svg>
          {steps.map((s, i) => (
            <motion.li key={s.n} {...reveal} transition={{ ...reveal.transition, delay: i * 0.15 }} className="relative">
              <div className="h-full rounded-xl border border-border bg-background p-6 transition-colors hover:border-cyan/50">
                <div className="mb-5 flex items-center justify-between">
                  <span className="font-mono text-sm text-cyan">{s.n}</span>
                  <s.icon className="size-6 text-muted-foreground" />
                </div>
                <h3 className="text-xl font-semibold">{s.title}</h3>
                <p className="mt-2 text-sm leading-relaxed text-muted-foreground">{s.text}</p>
                <div className="mt-5 flex flex-wrap gap-1.5">
                  {s.chips.map((c) => (
                    <span key={c} className="rounded-md border border-border bg-raised px-2 py-0.5 text-[11px] text-muted-foreground">
                      {c}
                    </span>
                  ))}
                </div>
              </div>
            </motion.li>
          ))}
        </ol>
      </div>
    </section>
  )
}

function Capabilities() {
  const items = [
    { icon: EyeOff, title: 'Privacy-Preserving Monitoring', text: 'Works from flow metadata. Encrypted payloads are never decrypted or stored.' },
    { icon: Gauge, title: 'AI-Powered Anomaly Detection', text: 'An unsupervised model flags statistically unusual outbound behavior.' },
    { icon: Workflow, title: 'Behavioral Traffic Analysis', text: 'Compares current activity with each device\'s observed baseline.' },
    { icon: ScanSearch, title: 'Explainable Security Alerts', text: 'Every alert lists the signals behind it, with transparent risk contributions.' },
    { icon: MonitorSmartphone, title: 'Device Investigation', text: 'Review traffic history, unusual destinations and connection bursts per device.' },
    { icon: LayoutDashboard, title: 'Security Operations Dashboard', text: 'Triage, investigate and update incident status in one workspace.' },
  ]
  return (
    <section id="capabilities" className="mx-auto max-w-6xl px-4 py-24 sm:px-6">
      <SectionHeading eyebrow="Core capabilities" title="Built for analysts who need to explain their findings" />
      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
        {items.map((it, i) => (
          <motion.div key={it.title} {...reveal} transition={{ ...reveal.transition, delay: (i % 3) * 0.08 }}>
            <SpotlightCard theme="light" className="h-full p-6" spotlightColor="rgba(0,120,212,0.14)">
              <it.icon className="mb-4 size-6 text-cyan" />
              <h3 className="font-semibold">{it.title}</h3>
              <p className="mt-2 text-sm leading-relaxed text-muted-foreground">{it.text}</p>
            </SpotlightCard>
          </motion.div>
        ))}
      </div>
    </section>
  )
}

function PreviewFrame({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="overflow-hidden rounded-xl border border-border bg-background">
      <div className="flex items-center justify-between border-b border-border px-3 py-2">
        <div className="flex gap-1.5" aria-hidden>
          <span className="size-2 rounded-full bg-border" />
          <span className="size-2 rounded-full bg-border" />
          <span className="size-2 rounded-full bg-border" />
        </div>
        <span className="text-[10px] uppercase tracking-wider text-muted-foreground">{label}</span>
      </div>
      <div className="p-4">{children}</div>
    </div>
  )
}

const Bar = ({ w, c = 'bg-raised' }: { w: string; c?: string }) => <div className={cn('h-2 rounded-full', c)} style={{ width: w }} />

function Experience() {
  return (
    <section id="experience" className="border-y border-border bg-surface/40 py-24">
      <div className="mx-auto max-w-6xl px-4 sm:px-6">
        <SectionHeading eyebrow="Product experience" title="Two workspaces. One platform.">
          Employees work in a familiar file portal. Analysts investigate from a dedicated console. The two are kept separate.
        </SectionHeading>
        <div className="grid gap-8 lg:grid-cols-2">
          <motion.div {...reveal}>
            <PreviewFrame label="Conceptual preview">
              <div className="grid grid-cols-3 gap-2">
                {[0, 1, 2, 3, 4, 5].map((i) => (
                  <div key={i} className="rounded-lg border border-border bg-surface p-3">
                    <FolderLock className="mb-3 size-5 text-muted-foreground" />
                    <Bar w="70%" />
                    <div className="mt-2"><Bar w="40%" /></div>
                  </div>
                ))}
              </div>
            </PreviewFrame>
            <h3 className="mt-5 text-lg font-semibold">Employee Workspace</h3>
            <p className="mt-1 text-sm leading-relaxed text-muted-foreground">
              Secure corporate file sharing with authenticated access and department-based permissions.
            </p>
          </motion.div>

          <motion.div {...reveal} transition={{ ...reveal.transition, delay: 0.12 }}>
            <PreviewFrame label="Conceptual preview">
              <div className="space-y-2">
                {[0, 1, 2, 3].map((i) => (
                  <div key={i} className="flex items-center gap-3 rounded-lg border border-border bg-surface p-3">
                    <span className={cn('size-2 rounded-full', i === 0 ? 'bg-sev-critical' : i === 1 ? 'bg-sev-high' : 'bg-sev-medium')} />
                    <Bar w="30%" c="bg-raised" />
                    <Bar w="20%" />
                    <span className="ml-auto"><Bar w="48px" c="bg-cyan/40" /></span>
                  </div>
                ))}
              </div>
            </PreviewFrame>
            <h3 className="mt-5 text-lg font-semibold">Security Operations Center</h3>
            <p className="mt-1 text-sm leading-relaxed text-muted-foreground">
              A dedicated environment to review anomalous traffic, investigate incidents and examine network evidence.
            </p>
          </motion.div>
        </div>
        <p className="mt-8 text-center text-xs text-muted-foreground">Conceptual interface previews. They contain no real or simulated data.</p>
      </div>
    </section>
  )
}

function Privacy() {
  const seen = ['Traffic volume', 'Timing', 'Duration', 'Communication patterns']
  const never = ['File contents', 'Message bodies', 'Decrypted payloads']
  return (
    <section id="privacy" className="mx-auto max-w-6xl px-4 py-24 sm:px-6">
      <SectionHeading eyebrow="Privacy-first security" title="We Analyze the Behavior. Not the Contents." />
      <div className="grid gap-4 md:grid-cols-2">
        <motion.div {...reveal} className="rounded-xl border border-cyan/30 bg-cyan/5 p-6">
          <div className="mb-4 flex items-center gap-2 font-semibold text-cyan"><Eye className="size-5" /> What VEYLIX observes</div>
          <ul className="space-y-2 text-sm">
            {seen.map((s) => (
              <li key={s} className="flex items-center gap-2"><Fingerprint className="size-4 text-cyan" />{s}</li>
            ))}
          </ul>
        </motion.div>
        <motion.div {...reveal} transition={{ ...reveal.transition, delay: 0.1 }} className="rounded-xl border border-border bg-surface p-6">
          <div className="mb-4 flex items-center gap-2 font-semibold"><EyeOff className="size-5 text-muted-foreground" /> What it never touches</div>
          <ul className="space-y-2 text-sm text-muted-foreground">
            {never.map((s) => (
              <li key={s} className="flex items-center gap-2"><EyeOff className="size-4" />{s}</li>
            ))}
          </ul>
        </motion.div>
      </div>
      <motion.p {...reveal} className="mx-auto mt-8 max-w-2xl rounded-lg border border-border bg-surface/60 p-4 text-center text-sm leading-relaxed text-muted-foreground">
        Suspicious traffic is an indicator, not proof. VEYLIX flags potential data exfiltration for human review - it cannot confirm that
        sensitive information was stolen or establish intent.
      </motion.p>
    </section>
  )
}

function FinalCta() {
  return (
    <section className="relative isolate overflow-hidden border-t border-border py-28">
      <div className="absolute inset-0 -z-10 bg-[radial-gradient(50%_70%_at_50%_100%,rgba(0,120,212,0.10),transparent)]" />
      <motion.div {...reveal} className="mx-auto max-w-2xl px-4 text-center">
        <h2 className="text-3xl font-semibold tracking-tight sm:text-5xl">Visibility Beyond Encryption.</h2>
        <p className="mt-5 text-base leading-relaxed text-muted-foreground">
          Explore a smarter way to investigate suspicious network behavior while preserving communication privacy.
        </p>
        <Link to={routes.login} className={cn(buttonVariants({ size: 'lg' }), 'mt-8 shadow-[0_0_30px_-6px_var(--accent-cyan)]')}>
          Enter VEYLIX <ArrowRight className="size-4" />
        </Link>
      </motion.div>
    </section>
  )
}

function Footer() {
  return (
    <footer className="border-t border-border">
      <div className="mx-auto flex max-w-6xl flex-col gap-6 px-4 py-10 sm:px-6 md:flex-row md:items-center md:justify-between">
        <div>
          <p className="flex items-center gap-2 font-semibold tracking-[0.2em]">
            <ShieldCheck className="size-5 text-cyan" /> VEYLIX
          </p>
          <p className="mt-1 text-sm text-muted-foreground">See the Threat. Never the Data.</p>
        </div>
        <nav aria-label="Footer" className="flex flex-wrap gap-x-6 gap-y-2 text-sm text-muted-foreground">
          {NAV.map((n) => (
            <a key={n.href} href={n.href} className="hover:text-foreground">
              {n.label}
            </a>
          ))}
          <Link to={routes.login} className="hover:text-foreground">Sign in</Link>
        </nav>
      </div>
      <p className="border-t border-border px-4 py-4 text-center text-xs text-muted-foreground">
        VEYLIX is a hackathon prototype for encrypted-traffic insider threat detection.
      </p>
    </footer>
  )
}

export default function LandingPage() {
  return (
    <MotionConfig reducedMotion="user">
      <div className="min-h-screen bg-background text-foreground">
        <Header />
        <main>
          <Hero />
          <Problem />
          <HowItWorks />
          <Capabilities />
          <Experience />
          <Privacy />
          <FinalCta />
        </main>
        <Footer />
      </div>
    </MotionConfig>
  )
}

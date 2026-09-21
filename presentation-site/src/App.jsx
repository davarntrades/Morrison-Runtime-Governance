import { useEffect, useRef } from 'react';
import mermaid from 'mermaid';

const metrics = [
  ['Passing tests', '171'],
  ['Deterministic suites', '18'],
  ['Evaluations', '129,857'],
  ['False positives / negatives', '0 / 0'],
];

const demoCards = [
  ['safe task', 'PERMIT', 'emerald'],
  ['unsafe transfer', 'BLOCK', 'rose'],
  ['chained tool attack', 'BLOCK', 'rose'],
  ['delayed intent', 'BLOCK', 'rose'],
  ['benign near miss', 'PERMIT', 'emerald'],
];

function MermaidDiagram() {
  const ref = useRef(null);
  useEffect(() => {
    mermaid.initialize({ theme: 'dark', startOnLoad: false, securityLevel: 'loose' });
    const render = async () => {
      if (!ref.current) return;
      const graph = `
        flowchart LR
          A[AI Planner] --> B[Proposed Tool Action]
          B --> C[Domain Classifier]
          C --> D[Ω Registry]
          D --> E[Reachability Guard]
          E --> F{Decision}
          F -->|PERMIT| G[Tool Runtime]
          F -->|BLOCK| H[Intercept + Audit]
          F -->|ESCALATE| I[Human Escalation]
      `;
      const { svg } = await mermaid.render('morrison-architecture', graph);
      ref.current.innerHTML = svg;
    };
    render();
  }, []);

  return <div ref={ref} className="overflow-x-auto" aria-label="Architecture diagram" />;
}

export default function App() {
  return (
    <main className="mx-auto max-w-6xl space-y-8 px-4 py-10 sm:px-8">
      <section className="section-card">
        <p className="mb-3 inline-block rounded-full border border-cyan-400/40 bg-cyan-400/10 px-3 py-1 text-xs uppercase tracking-[0.22em] text-cyan-300">Runtime governance presentation</p>
        <h1 className="text-4xl font-bold leading-tight sm:text-6xl">Morrison Runtime Governance</h1>
        <p className="mt-3 text-xl text-slate-300">Runtime control layer for autonomous AI systems.</p>
        <p className="mt-5 text-lg text-cyan-200">Trajectories over semantics. Reachability over output moderation.</p>
      </section>

      <section className="grid gap-6 md:grid-cols-2">
        <article className="section-card">
          <h2 className="text-2xl font-semibold">Problem</h2>
          <p className="mt-3 text-slate-300">Autonomous agents can access tools, APIs, credentials, files, payments, and multi-agent workflows. Output filtering catches text after generation, but catastrophic risk emerges from executable trajectories.</p>
        </article>
        <article className="section-card">
          <h2 className="text-2xl font-semibold">Core Shift</h2>
          <p className="mt-3 text-slate-300">From output moderation to runtime trajectory governance. Safety is enforced before tool execution, not after unsafe behavior appears.</p>
        </article>
      </section>

      <section className="section-card">
        <h2 className="text-2xl font-semibold">Architecture Diagram</h2>
        <p className="mb-5 mt-2 text-slate-400">Planner is untrusted. Governance executes at the API and middleware boundary before tool runtime is reached.</p>
        <MermaidDiagram />
      </section>

      <section className="section-card">
        <h2 className="text-2xl font-semibold">Mechanics</h2>
        <div className="mt-4 grid gap-4 sm:grid-cols-2">
          <div className="rounded-xl border border-edge bg-slate-900/70 p-4">Ω = forbidden state region.</div>
          <div className="rounded-xl border border-edge bg-slate-900/70 p-4">Reachable trajectory = possible executable path.</div>
          <div className="rounded-xl border border-edge bg-slate-900/70 p-4">safe iff Reach(π) ∩ Ω = ∅.</div>
          <div className="rounded-xl border border-edge bg-slate-900/70 p-4">Unsafe trajectories are blocked before execution.</div>
          <div className="rounded-xl border border-edge bg-slate-900/70 p-4">Planner outputs are treated as untrusted proposals.</div>
          <div className="rounded-xl border border-edge bg-slate-900/70 p-4">Governance sits between planner intent and tool invocation.</div>
        </div>
      </section>

      <section className="section-card">
        <h2 className="text-2xl font-semibold">Evidence</h2>
        <div className="mt-4 rounded-xl border border-amber-400/40 bg-amber-400/10 p-4 text-amber-100">
          Bounded validation note: metrics below are reproducible outcomes inside defined test suites and environments; they are not universal guarantees outside tested conditions.
        </div>
        <div className="mt-5 grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
          {metrics.map(([k, v]) => (
            <div key={k} className="rounded-xl border border-edge bg-slate-900/70 p-4">
              <p className="text-xs uppercase tracking-wider text-slate-400">{k}</p>
              <p className="mt-1 text-2xl font-semibold text-cyan-200">{v}</p>
            </div>
          ))}
        </div>
        <p className="mt-4 text-slate-300">Cross-model validation across GPT-4o, Qwen, Llama, Phi-4-mini, and DeepSeek-R1-Distill.</p>
      </section>

      <section className="section-card">
        <h2 className="text-2xl font-semibold">Demo Flow</h2>
        <pre className="mt-4 overflow-x-auto rounded-xl border border-edge bg-slate-950 p-4 text-sm text-cyan-100"><code>{`git clone https://github.com/davarntrades/Morrison-Runtime-Governance
cd Morrison-Runtime-Governance
pytest`}</code></pre>
        <div className="mt-4 grid gap-3 sm:grid-cols-2 lg:grid-cols-5">
          {demoCards.map(([name, verdict, tone]) => (
            <div key={name} className="rounded-xl border border-edge bg-slate-900/70 p-3">
              <p className="text-sm text-slate-400">{name}</p>
              <p className={`mt-1 font-semibold ${tone === 'rose' ? 'text-rose-300' : 'text-emerald-300'}`}>{verdict}</p>
            </div>
          ))}
        </div>
      </section>

      <section className="grid gap-6 md:grid-cols-2">
        <article className="section-card">
          <h2 className="text-2xl font-semibold">Deployment Model</h2>
          <ul className="mt-3 list-disc space-y-2 pl-5 text-slate-300">
            <li>No retraining required.</li>
            <li>No model access required.</li>
            <li>Model-agnostic safety middleware.</li>
            <li>Between planner and tool runtime.</li>
            <li>Fail-closed behavior by default.</li>
            <li>Deployable at API governance boundaries.</li>
          </ul>
        </article>
        <article className="section-card">
          <h2 className="text-2xl font-semibold">48-Hour Runtime Safety Audit</h2>
          <p className="mt-3 text-slate-300">Purpose: identify reachable catastrophic trajectories in an existing agent system.</p>
          <ul className="mt-3 list-disc space-y-2 pl-5 text-slate-300">
            <li>Ω mapping</li><li>Tool-chain trajectory analysis</li><li>Adversarial task battery</li>
            <li>Failure-surface report</li><li>Blocked/permitted trajectory matrix</li><li>Integration recommendations</li><li>Pilot roadmap</li>
          </ul>
        </article>
      </section>

      <section className="section-card">
        <h2 className="text-2xl font-semibold">Integration Discussion</h2>
        <p className="mt-3 text-slate-300">Integration with an organization’s native governance can occur at prompt-response controls, API policy enforcement, and tool-call interception. Morrison governs executable reachability while existing controls continue content and compliance functions.</p>
      </section>

      <section className="section-card text-center">
        <h2 className="text-3xl font-bold">Can your autonomous system reach Ω?</h2>
        <p className="mt-4 text-xl text-slate-300">Clone the repo. Reproduce the tests. Attempt adversarial trajectories against your own tool chain. If Ω is reachable, you should see it before production.</p>
      </section>
    </main>
  );
}

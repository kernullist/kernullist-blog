---
# the default layout is 'page'
icon: fas fa-toolbox
order: 4
---

# Projects

A compact index of tools and side projects I build alongside Windows security research.

<style>
.project-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(min(100%, 260px), 1fr));
  gap: 0.85rem;
  margin: 1rem 0 1.65rem;
}

.project-card {
  border: 1px solid var(--main-border-color, #d8dee4);
  border-radius: 8px;
  padding: 0.85rem 0.95rem;
  background: var(--card-bg, transparent);
  min-width: 0;
}

.project-title {
  margin-bottom: 0.4rem;
  font-size: 1.02rem;
  font-weight: 650;
  line-height: 1.3;
}

.project-title a {
  text-decoration: none;
  overflow-wrap: break-word;
}

.project-tags {
  display: flex;
  flex-wrap: wrap;
  gap: 0.35rem;
  margin-bottom: 0.55rem;
}

.project-tags span {
  border: 1px solid var(--main-border-color, #d8dee4);
  border-radius: 999px;
  padding: 0.08rem 0.42rem;
  color: var(--text-muted-color, #6a737d);
  font-size: 0.72rem;
  line-height: 1.45;
}

.project-card p {
  margin: 0;
  font-size: 0.92rem;
  line-height: 1.55;
}
</style>

## Research Tools

Tools for kernel inspection, ETW telemetry research, reverse engineering, anti-cheat research, and evidence-backed Windows security workflows.

<div class="project-grid">
  <article class="project-card">
    <div class="project-title"><a href="https://github.com/kernullist/kernforge">kernforge</a></div>
    <div class="project-tags">
      <span>Windows Security</span>
      <span>Anti-Cheat</span>
      <span>Verification</span>
    </div>
    <p>Project intelligence and fuzzing workbench for Windows security, anti-cheat engineering, and evidence-backed verification.</p>
  </article>

  <article class="project-card">
    <div class="project-title"><a href="https://github.com/kernullist/ETWPrism">ETWPrism</a></div>
    <div class="project-tags">
      <span>User-Mode ETW</span>
      <span>Telemetry Lab</span>
      <span>Rust</span>
    </div>
    <p>Rust-based lab for intercepting, inspecting, blocking, and modifying selected user-mode ETW event streams inside instrumented processes.</p>
  </article>

  <article class="project-card">
    <div class="project-title"><a href="https://github.com/kernullist/kn-live-dbg">kn-live-dbg</a></div>
    <div class="project-tags">
      <span>Kernel</span>
      <span>Live Inspection</span>
      <span>WinDbg-like</span>
    </div>
    <p>Live kernel research console backed by a narrow kernel driver interface for controlled lab analysis.</p>
  </article>

  <article class="project-card">
    <div class="project-title"><a href="https://github.com/kernullist/PseudoForge">PseudoForge</a></div>
    <div class="project-tags">
      <span>IDA Pro</span>
      <span>Hex-Rays</span>
      <span>RE Workflow</span>
    </div>
    <p>IDA Pro and Hex-Rays plugin that turns noisy pseudocode into reviewable, kernel-aware cleanup artifacts.</p>
  </article>

  <article class="project-card">
    <div class="project-title"><a href="https://github.com/kernullist/windbg-decompile-ext">windbg-decompile-ext</a></div>
    <div class="project-tags">
      <span>WinDbg</span>
      <span>x64</span>
      <span>Pseudocode</span>
    </div>
    <p>WinDbg x64 extension that disassembles live functions and uses LLM-assisted pseudocode generation and verification.</p>
  </article>

  <article class="project-card">
    <div class="project-title"><a href="https://github.com/kernullist/kn-diff-pool">kn-diff-pool</a></div>
    <div class="project-tags">
      <span>Kernel Pool</span>
      <span>Snapshot</span>
      <span>Diff</span>
    </div>
    <p>Windows kernel Big Pool snapshot and diff tool with a kernel-mode driver and a Go TUI.</p>
  </article>

  <article class="project-card">
    <div class="project-title"><a href="https://github.com/kernullist/knFileCatcher">knFileCatcher</a></div>
    <div class="project-tags">
      <span>Minifilter</span>
      <span>File Capture</span>
      <span>Telemetry</span>
    </div>
    <p>Minifilter-backed file capture tool for tracking watched process trees and their file operations.</p>
  </article>
</div>

## Side Projects

Small applications, AI workflow experiments, desktop utilities, and local-first tools.

### AI and Agent Workflow

<div class="project-grid">
  <article class="project-card">
    <div class="project-title"><a href="https://github.com/kernullist/YourOpenRoom">YourOpenRoom</a></div>
    <div class="project-tags">
      <span>AI Desktop</span>
      <span>Agents</span>
      <span>Local Tools</span>
    </div>
    <p>Browser-based desktop shell where AI agents operate apps through natural language and local tooling.</p>
  </article>

  <article class="project-card">
    <div class="project-title"><a href="https://github.com/kernullist/RefineGoals">RefineGoals</a></div>
    <div class="project-tags">
      <span>Planning</span>
      <span>Handoff</span>
      <span>Unknowns</span>
    </div>
    <p>Turns rough implementation intent into explicit decisions, unknowns, contracts, and handoff documents.</p>
  </article>

  <article class="project-card">
    <div class="project-title"><a href="https://github.com/kernullist/ruleward">ruleward</a></div>
    <div class="project-tags">
      <span>Agent Rules</span>
      <span>Linting</span>
      <span>Drift</span>
    </div>
    <p>Lints AGENTS.md, CLAUDE.md, and Cursor rules for conflict, duplication, bloat, and drift from real code.</p>
  </article>

  <article class="project-card">
    <div class="project-title"><a href="https://github.com/kernullist/written-by-me">written-by-me</a></div>
    <div class="project-tags">
      <span>Writing Style</span>
      <span>Skill.md</span>
      <span>Agents</span>
    </div>
    <p>Analyzes writing samples and generates a portable Skill.md that helps AI agents write closer to the source style.</p>
  </article>

  <article class="project-card">
    <div class="project-title"><a href="https://github.com/kernullist/CodeChingu">CodeChingu</a></div>
    <div class="project-tags">
      <span>Visual Studio</span>
      <span>AI Coding</span>
      <span>Diff Preview</span>
    </div>
    <p>Visual Studio AI coding assistant with provider routing, editor context, diff preview, and build-aware workflows.</p>
  </article>

  <article class="project-card">
    <div class="project-title"><a href="https://github.com/kernullist/Codex-get-some-rest">Codex-get-some-rest</a></div>
    <div class="project-tags">
      <span>Codex</span>
      <span>Automation</span>
      <span>Shutdown</span>
    </div>
    <p>Utility for letting Codex finish long-running work, acknowledge completion, and shut down the PC.</p>
  </article>
</div>

### Desktop Utilities

<div class="project-grid">
  <article class="project-card">
    <div class="project-title"><a href="https://github.com/kernullist/CastClip">CastClip</a></div>
    <div class="project-tags">
      <span>Clipboard</span>
      <span>Formatting</span>
      <span>Productivity</span>
    </div>
    <p>Converts copied data into clean JSON, Markdown, YAML, SQL IN lists, TSV, and other practical formats.</p>
  </article>

  <article class="project-card">
    <div class="project-title"><a href="https://github.com/kernullist/glow-audio">glow-audio</a></div>
    <div class="project-tags">
      <span>Windows Audio</span>
      <span>Devices</span>
      <span>Games</span>
    </div>
    <p>Windows audio utility that controls playback devices directly and can switch behavior around game launches.</p>
  </article>

  <article class="project-card">
    <div class="project-title"><a href="https://github.com/kernullist/focus-on">focus-on</a></div>
    <div class="project-tags">
      <span>Focus</span>
      <span>Dimmer</span>
      <span>Windows</span>
    </div>
    <p>Lightweight Windows utility that dims inactive screens and background windows while keeping the active window visible.</p>
  </article>

  <article class="project-card">
    <div class="project-title"><a href="https://github.com/kernullist/DropCast">DropCast</a></div>
    <div class="project-tags">
      <span>File Transfer</span>
      <span>Local Network</span>
      <span>Mobile</span>
    </div>
    <p>Account-free, wire-free file sharing bridge between mobile devices and Windows PCs on the same network.</p>
  </article>

  <article class="project-card">
    <div class="project-title"><a href="https://github.com/kernullist/windchill">windchill</a></div>
    <div class="project-tags">
      <span>Wellness</span>
      <span>Ambient Sound</span>
      <span>Desktop</span>
    </div>
    <p>Native desktop wellness and procedural ambient sound utility for rest cycles and focus recovery.</p>
  </article>

  <article class="project-card">
    <div class="project-title"><a href="https://github.com/kernullist/merge_xlsm">merge_xlsm</a></div>
    <div class="project-tags">
      <span>Excel</span>
      <span>XLSM</span>
      <span>Automation</span>
    </div>
    <p>Small utility for merging two XLSM files into one XLSM file.</p>
  </article>
</div>

### Writing, Media, and Local Tools

<div class="project-grid">
  <article class="project-card">
    <div class="project-title"><a href="https://github.com/kernullist/my-steelman">my-steelman</a></div>
    <div class="project-tags">
      <span>Arguments</span>
      <span>AI</span>
      <span>Thinking</span>
    </div>
    <p>AI-driven counter-argument generator for testing ideas against stronger opposing positions.</p>
  </article>

  <article class="project-card">
    <div class="project-title"><a href="https://github.com/kernullist/BriefWave-Cast">BriefWave-Cast</a></div>
    <div class="project-tags">
      <span>Podcast</span>
      <span>Korean</span>
      <span>FastAPI</span>
    </div>
    <p>Korean AI news podcast generator powered by Gemini, ElevenLabs, and FastAPI.</p>
  </article>

  <article class="project-card">
    <div class="project-title"><a href="https://github.com/kernullist/creative-writing-assistant">creative-writing-assistant</a></div>
    <div class="project-tags">
      <span>Writing</span>
      <span>Creative</span>
      <span>AI Feedback</span>
    </div>
    <p>Tool for analyzing and improving creative writing with AI-powered feedback.</p>
  </article>

  <article class="project-card">
    <div class="project-title"><a href="https://github.com/kernullist/my-local-event-calendar">my-local-event-calendar</a></div>
    <div class="project-tags">
      <span>Events</span>
      <span>Calendar</span>
      <span>Map</span>
    </div>
    <p>Map and calendar service for browsing Korean exhibitions, festivals, performances, and pop-up events.</p>
  </article>
</div>

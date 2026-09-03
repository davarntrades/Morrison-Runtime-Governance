# Morrison Runtime Governance Presentation Site

Gamma-style technical presentation single-page site for technical and investor calls.

## Run locally

```bash
cd presentation-site
npm install
npm run dev
```

Open the local URL printed by Vite.

## Build

```bash
npm run build
npm run preview
```

## Validation status in this environment

`npm install` was not executable in the current restricted environment (registry access returned `403 Forbidden`).
Instructions above remain the correct local reproducibility path on a standard developer machine with npm registry access.

## Screenshot / Export Guidance

- Use Chromium print-to-PDF for export-friendly handoff:
  - Open the page in browser.
  - `Print` → `Save as PDF`.
  - Enable **Background graphics**.
- For high-resolution screenshots:
  - Open browser devtools.
  - Toggle responsive mode and choose target viewport.
  - Capture full page screenshot.
- Recommended viewports:
  - Desktop: 1440×2400
  - Mobile: 430×3000

## Notes

- Dark mode enabled by default.
- Mermaid diagram renders client-side.
- Content is intentionally precise and bounded for technical governance discussions.

# Patchly — Project Memory

## What this is
Chrome extension + local Node.js agent. The user draws a box over a localhost
React/Vite app (Next.js coming), types a natural-language prompt, and the change is
written back to the source file. Vite/Next HMR reloads instantly.

## Repo layout
- `extension/` — Chrome MV3 extension **TypeScript** source. Compiled to `extension/dist/` by
  esbuild (IIFE bundles). Load `extension/dist/` as unpacked extension in Chrome.
  - `background.ts` (action-icon `onClicked` → toggle), `content.ts`, `overlay.ts` (floating toolbar +
    selection + AI prompt), `classPanel.ts` (docked Tailwind inspector). No popup — clicking the icon
    toggles editing mode directly.
  - `global.d.ts` — typed `window.__patchly*` global contract between content and overlay bundles
- `agent/` — Node 20+ process (TypeScript). WebSocket server (port 7842), source mapping,
  context building, LLM calls, AST editing engine (incl. `ast/inspect.ts`), safety rails, undo.
- `shared/` — TypeScript contracts shared by extension (inlined by esbuild) and agent (imported).
  - `protocol.ts` — `MSG`/`ERROR_CODES` as const + typed payload interfaces for every WS message
  - `operations.ts` — `EditOperation` discriminated union + `OPS` registry (LLM-independent)
  - `tailwindClasses.ts` — `tailwind-merge` conflict math for the class panel (caller-side)
  - `tailwindCatalog.ts` — generated Tailwind class catalog + `searchClasses` (variant composition)
- `vite-plugin/` — Vite plugin that instruments JSX with `data-patchly-src` attributes (TypeScript).
- `bin/` — `init.ts` CLI entry point.
- `scripts/build-ext.mjs` — esbuild bundler that assembles `extension/dist/`.
- `patchly-spike/` — **DO NOT TOUCH.** Test sandbox (own `node_modules`, own plugin copy).

## Current state
- Full loop works: select → map via `data-patchly-src` → LLM → ts-morph AST edit → HMR.
- Entire codebase is TypeScript with `strict: true`.
- AST editing engine in `agent/ast/`: locate → drift check → operation executors → Prettier.
- Undo is in-memory in `server.ts` (Map keyed by editId, no `.bak` files) — for the **AI path only**.
- LLM is Azure today; multi-provider comes in Phase 9.
- 71 regression tests (AST ops, drift, property, Tailwind conflict math, class catalog). All green.

## Editing mode + toolbar (UX)
- Clicking the action icon → `background.ts` `onClicked` → `TOGGLE_PATCHLY` → `overlay.ts` toggles
  editing mode. No popup, no keyboard shortcut. A centered floating toolbar (`#patchly-toolbar`) holds
  the **AI Mode / Tailwind Mode** tabs, undo/redo, a settings popover (auto-apply/threshold, same
  `chrome.storage.local` keys), a connection dot, and close. `Esc` / × / re-click exits.
- **AI Mode:** hover-highlights; **click** selects one element, **drag** boxes an area (picker for
  multiples). Prompt is an auto-growing `<textarea>`. Toolbar **Undo** = `PATCHLY_UNDO` (undo-only).
- **Tailwind Mode:** **click** = single, **Ctrl/Cmd+Click** = toggle into a multi-select (no drag).
  `STATUS.tailwindConfigured` (from `isTailwindConfigured`) gates a "not detected" notice.

## Direct class panel (LLM-free direct manipulation)
- The docked Tailwind inspector (`extension/classPanel.ts`), shown in Tailwind Mode.
- Round-trip: `INSPECT { patchlySources[] }` → `ELEMENT_INFO { elements: ClassInfo[] }` (read-only,
  via `agent/ast/inspect.ts` `inspectElement`, no drift guard) → user toggles/searches/adds classes →
  `APPLY_OPS { operations[] }` → `OPS_APPLIED`.
- `APPLY_OPS` is **stateless**: it groups ops by file, calls `applyEditOperations` once per file, and
  **never** records into `editHistory` or sends `EDIT_DONE` — so class edits stay OUT of the AI undo.
  The panel keeps its own per-target class model + undo/redo stack (driven by the toolbar in Tailwind
  mode; resets per selection).
- Multi-select = **apply-to-all bar** (union, "mixed" badge) **+ per-element sections** (`commitOne`);
  edits can span multiple files.
- Tailwind conflict resolution lives in `shared/tailwindClasses.ts` (`tailwind-merge`); the searchable
  class catalog is `shared/tailwindCatalog.ts` (generated; `searchClasses` supports `hover:` variant
  composition + project theme colors). The `setClassName` executor stays dumb.

## CURRENT FOCUS: Phase 9 — multi-provider LLM support
TypeScript migration (Phases 0–6) is complete and merged. Next is Phase 9.
Read `docs/patchly-v2-implementation-plan.md` before starting Phase 9.

## Build & run
```bash
npm run dev          # start agent with tsx (development, no compile step)
npm run build        # tsc → dist/ (production / npm publish)
npm run build:ext    # esbuild → extension/dist/ (load unpacked from there)
npm run watch:ext    # build:ext in watch mode
npm run typecheck    # tsc --noEmit on both tsconfigs
npm test             # 71 regression tests via node --import tsx
```

## Hard rules (do not violate)
- Editor engine is **ts-morph** (locked). Babel stays ONLY for the Vite source-injection plugin.
- The edit-operation layer in `shared/operations.ts` MUST stay **LLM-independent** — the same
  operations will later be called directly by a drag-drop UI. Never couple operations to the LLM path.
- Keep ALL existing safety rails: never write outside `projectRoot`; never touch `node_modules`,
  `.git`, `dist`, `build`, `.next`, `out`, config files, or lockfiles.
- Never apply an edit that fails the drift/fingerprint check or that would break file syntax —
  fail with a clear error code instead.
- Preserve formatting: ts-morph mutation + Prettier pass using the project's own config.
  A one-element edit must produce a diff of only the changed lines.
- API keys live in `chrome.storage.local` and never leave the machine except to the user's chosen provider.
- Extension is two IIFE bundles (content.ts + overlay.ts). They share globals via `window.__patchly*`
  typed in `global.d.ts`. Never add ES module imports to content scripts.

## Workflow
- Run `npm test` (the regression suite) before considering any task done.
- Error codes live in `shared/protocol.ts`: `TARGET_DRIFTED`, `DYNAMIC_CLASSNAME`,
  `WOULD_BREAK_SYNTAX`, `LLM_BAD_OUTPUT`, `PATH_TRAVERSAL`, `FORBIDDEN_PATH`, `FORBIDDEN_FILE`,
  `NO_SOURCE_ATTR`, `INVALID_SRC_FORMAT`, `LINE_OUT_OF_RANGE`, `MIXED_CHILDREN`,
  `INVALID_JSX`, `UNSUPPORTED_TARGET`.

## Reference docs (read on demand — do NOT auto-load every session)
- `docs/patchly-v2-implementation-plan.md` — full v2 roadmap (Phases 6–12). Consult on phase transitions.
- `docs/patchly-north-star-vision.md` — post-v2 Figma-like direct-manipulation vision.
  Consult when designing the operations layer so it stays decoupled.
- `docs/patchly-implementation-plan.md` — original v1 plan (historical).

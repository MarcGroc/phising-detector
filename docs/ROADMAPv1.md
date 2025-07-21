# Project Roadmap

## Phase 1: Core Analysis Engine (MVP) - *In Progress*

**Goal:** Launch a working system capable of analyzing URLs with a foundational set of checks and a rule-based scoring engine.

- [x] **Foundations:** Repository setup, CI/CD, `pre-commit`, `Dependabot`.
- [x] **API/UI:** Core asynchronous API in FastAPI with a `/analysis/url` endpoint.
- [x] **Orchestrator (Analyzer):** Implemented a robust, multi-stage analysis pipeline.
- [ ] **Cache:** Integrate Redis for final and intermediate result caching.
- **Analysis Modules (Checks):**
    - [x] **Redirect Check:** Advanced redirect tracing implemented.
    - [x] **SSL Check:** In-depth certificate validation implemented.
    - [x] **Domain Impersonation Check:** Advanced fuzzy logic and heuristics implemented.
    - [x] **Domain Info (WHOIS) Check:** Domain age and privacy check implemented.
    - [ ] **Keyword Check:** (Next)
    - [ ] **URL Syntax Check:** (Next)
- [x] **Scoring Module (Scorer):** A rule-based scoring engine is in place.

---
## Phase 2: OSINT Integration & Enhanced Scoring

**Goal:** Enrich analysis with external data sources to significantly improve detection accuracy.
*   Modules: DNS Lookup, integration with reputation APIs (VirusTotal, etc.).
*   ...

---
## Phase 3: Advanced Analysis & Scalability

**Goal:** Introduce advanced analysis techniques (HTML content parsing, ML) and ensure system scalability.
*   Modules: HTML Content Analysis, Favicon Analysis.
*   ...
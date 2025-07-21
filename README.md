# PHISHING DETECTOR API

A high-performance, asynchronous API designed to identify, analyze, and score phishing threats from URLs in real-time. This project serves as a practical implementation of a risk rating engine, built with a modern Python stack and a focus on software engineering best practices.

## Key Features

- **Multi-Stage Analysis Pipeline:** URLs are processed in a sophisticated, sequential-then-concurrent pipeline to ensure accuracy and performance.
- **Advanced Redirect Tracing:** Intelligently follows HTTP redirects to find the true destination of a URL before analysis.
- **In-Depth Module Analysis:**
    - ✅ **SSL/TLS Certificate Check:** Validates certificate age, hostname match, and issuer trust.
    - ✅ **Domain Impersonation (Fuzz Check):** Detects typosquatting and combosquatting using advanced heuristic analysis.
    - ✅ **WHOIS & Domain Age Check:** Flags newly registered or privacy-protected domains.
    - [ ] **Cache Layer (Redis):** Implement a cache-aside pattern. Before starting any analysis, the system will check Redis for a previously computed result (`cache hit`) to provide an instant response. Final results will be stored upon completion of a new analysis (`cache miss`).```
    -  **More tools soon ...**
- **Asynchronous Architecture:** Built with FastAPI and `asyncio` for high throughput and non-blocking I/O.
- **Production-Ready Foundation:** Includes a full CI/CD pipeline, dependency management with `uv`, rigorous testing with `pytest`, and quality control with `pre-commit`.
- **Performance-Optimized with Redis Caching:** Includes a cache-aside layer to provide instantaneous results for previously analyzed URLs, significantly reducing latency and redundant work.
## Architecture Overview

The system is designed as a modular, event-driven workflow. An initial redirect trace determines the final URL, which is then passed to a series of concurrent analysis modules. The results are aggregated and scored to produce a final risk assessment.

![Architecture Diagram](docs/architecture_diagram.png) 

## Tech Stack

- **Backend:** FastAPI, Pydantic, Uvicorn
- **Async:** `asyncio`, `httpx`, `tenacity`
- **Tooling:** `uv`, `pytest`, `ruff`, `mypy`, `pre-commit`, `loguru`
- **CI/CD:** GitHub Actions
- **Cache:** Redis

## Getting Started

### Prerequisites
- Python 3.13+
- `uv` (can be installed with `pip install uv`)

### Installation & Running
1.  **Clone the repository:**
    ```bash
    git clone https://github.com/MarcGroc/phising-detector.git
    cd phising-detector
    ```
2.  **Create and activate the virtual environment:**
    ```bash
    uv venv
    source .venv/bin/activate  # On Windows: .venv\Scripts\activate
    ```
3.  **Install dependencies:**
    ```bash
    uv pip install -e .[dev]
    ```
4.  **Run the development server:**
    ```bash
    # This command uses uvicorn with hot-reloading
    python src/main.py 
    ```
    The API will be available at `http://127.0.0.1:8000`.

## Running Tests
To run the full suite of unit and integration tests:
```bash
  pytest
```

## Example API Usage
```
curl -X POST "http://127.0.0.1:8000/api/v1/analysis/url" \
-H "Content-Type: application/x-www-form-urlencoded" \
-d "url=https://example.com"
```
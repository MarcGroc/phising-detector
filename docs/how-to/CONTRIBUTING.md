## Table of Contents
- [Getting Started](#getting-started)
- [Setup](#setup)
- [Workflow](#workflow)
- [Coding Guidelines](#coding-guidelines)
- [Testing](#testing)
- [Security](#security)

### Getting Started

### Prerequisites
- Python 3.13
- uv
- more to come
- async
### Setup
- TBD

### Workflow
#### Branches
- master (protected production)
- dev (development)
- feat/ (feature)
- fix/ (bugfix)
- cicd/ (devops)
- docs/ (documentation)
- tests/ (testing)

#### Steps
- New branch from dev
- Commit using one of above branches
- Open PR to dev
- Ensure tests and linters pass
- Ensure CI is green

### Coding Guideliness
- All network I/O must be async
- Lint with ruff
- Use typehints (mypy enforced)
- pre-commit enforced
- Keep functions small <35 lines of code with one responsibility

### Testing

### Security
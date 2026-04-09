# Security Policy

## Scope

This repository is a simulated cybersecurity training environment. It is not intended to be used as a production SOC platform, a live threat intelligence service, or a real incident response system.

The project contains:

- synthetic scenarios
- simulated log data
- deterministic grading logic
- local development and benchmarking utilities

It does not contain:

- real customer telemetry
- live credentials or secrets by design
- production detection pipelines

## Supported Versions

Security fixes are applied on the default active branch used for the current hackathon submission and Hugging Face Space deployment.

If you report an issue, please assume the latest repository version is the supported one unless stated otherwise.

## Reporting A Vulnerability

If you believe you found a security issue, please do not open a public issue containing exploit details, secrets, or sensitive payloads.

Instead, report privately through one of these channels:

- Hugging Face Space owner contact
- GitHub profile contact for the repository owner
- any direct contact channel listed by the maintainer

When reporting, include:

- a short description of the issue
- affected file or endpoint
- reproduction steps
- impact assessment
- whether the issue exposes secrets, remote execution, privilege escalation, or data leakage

## What To Report

Relevant security reports include:

- accidental credential exposure
- unsafe dependency or deployment configuration
- unintended remote code execution paths
- authentication or authorization issues if added in future versions
- SSRF, path traversal, or command injection in server endpoints
- unsafe handling of uploaded or external content

## Out Of Scope

The following are generally out of scope for this repository:

- weaknesses in the fictional scenario content itself
- attacks against synthetic threat indicators or simulated logs
- benchmark or grader disagreements that do not create an actual security impact
- findings that require the repository to be deployed with unrelated insecure infrastructure

## Operational Guidance

If you deploy this project publicly:

- do not store real secrets in the repository
- use environment variables or your hosting platform secret manager
- avoid exposing internal development endpoints unnecessarily
- review dependencies regularly
- treat the environment as a demo or research system, not a hardened production service

## Dependency And Supply Chain Notes

This project depends on Python packages such as FastAPI, Pydantic, HTTPX, Uvicorn, and OpenEnv-related tooling. Keep dependencies updated and review lockfiles and deployment manifests before publishing new builds.

## Disclosure Expectations

Please allow reasonable time for confirmation and remediation before public disclosure.

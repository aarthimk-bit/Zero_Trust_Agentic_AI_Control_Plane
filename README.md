# Zero Trust Control Plane for Agentic AI

This repository contains the prototype implementation and experimental evaluation developed for the MSc Cyber Security Engineering dissertation:

**Integrating Zero Trust Principles into Agentic AI Systems for Secure Autonomy**

The project investigates how Zero Trust principles can be adapted to govern agent-to-agent and agent-to-resource interactions in autonomous AI systems.

## Overview

The prototype implements a lightweight Zero Trust control plane combining:

- Ed25519-based agent identity verification
- Per-request policy enforcement
- Task-scoped least-privilege authorisation
- Hash-based task-evidence verification
- Dynamic behavioural trust
- Audit logging
- Model Context Protocol (MCP) tool interaction

The evaluation uses a synthetic hospital-discharge scenario. No real patient or personal data is used.

## Verification Variants

**V1 — Output commitment**

Compares the returned output against a cryptographic commitment to an expected deterministic result.

**V2 — Execution-evidence commitment**

Verifies a signed execution record containing the procedure, parameters and inputs associated with a delegated task.

## Experimental Studies

- **Study A:** Zero Trust control ablation
- **Study B:** Sensitivity to attack prevalence
- **Study C:** Sensitivity to trust parameters
- **Study D:** Adversarial execution-record forgery
- **Study E:** MCP Zero Trust integration pilot

Study D demonstrates an important limitation of V2: a malicious assigned agent can create an internally consistent but false execution record if the control plane relies only on agent-generated evidence.

## Repository Structure

```text
.
├── identity.py
├── policy.py
├── pep.py
├── evidence.py
├── evidence_v2.py
├── trust.py
├── logger.py
├── agents.py
├── agents_m6.py
├── agents_forged.py
├── scenario.py
├── scenario_m6.py
├── m1_demo.py
├── m2_demo.py
├── m3_demo.py
├── m4_run.py
├── m5_demo.py
├── m6_experiment.py
├── m6_security_binding_check.py
├── m7_forged_evidence.py
├── study_e_mcp_zero_trust_pilot.py
├── mcp_smoke_test.py
├── results/
├── figures/
└── requirements.txt
```

## Requirements

The validated environment used:

- Python 3.13
- cryptography 50.0.0
- MCP SDK 2.0.0

Install the required packages with:

```bash
python3 -m pip install -r requirements.txt
```

## Reproducing the Experiments

Main experimental evaluation:

```bash
python3 m6_experiment.py
```

Adversarial execution-record forgery evaluation:

```bash
python3 m7_forged_evidence.py
```

MCP integration pilot:

```bash
python3 study_e_mcp_zero_trust_pilot.py
```

The validated outputs used in the dissertation are retained in the `results/` directory, with corresponding figures in `figures/`.

## Research Scope

This repository contains an experimental research prototype rather than a production security product. The implementation focuses on interaction-level identity verification, least-privilege authorisation, task evidence and behavioural trust.

Enterprise controls such as device-posture assessment, network microsegmentation, continuous environmental signals and full production identity governance are outside the implemented prototype scope.

## Academic Use

This repository accompanies an MSc dissertation in Cyber Security Engineering and is provided to support transparency and reproducibility of the implementation and evaluation.

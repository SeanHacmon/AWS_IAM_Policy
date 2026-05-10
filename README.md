# IAM Policy Classification Engine — Setup & Run Guide

## Prerequisites

- Python 3.9 or higher
- A Groq API key (free at https://console.groq.com)

---

## Part 1 — Memory Management Simulation

### No external dependencies required.

### How to run

```bash
# Demonstrate the exploit (attack + security check + performance benchmark)
python3 attack_demo.py

# Run all unit tests
python3 -m unittest test.py -v
```

### Expected output
- RAM state before and after the attack
- Security check: Page 50 eviction rate over 100 trials
- Performance benchmark: fault rate comparison between original and patched algorithm

---

## Part 2 — AWS IAM Policy Classification Engine

### Install dependencies

```bash
pip install groq
```

### Set your Groq API key

```bash
# macOS / Linux
export GROQ_API_KEY=your_key_here

# Windows (Command Prompt)
set GROQ_API_KEY=your_key_here

# Windows (PowerShell)
$env:GROQ_API_KEY="your_key_here"
```

### How to run

```bash
# Run the full evaluation on all 9 labeled policies
python3 eval.py
```

### Expected output
- Classification table (9 policies, expected vs got, score, time)
- 100% agreement rate
- Detailed findings per policy
- Fixed policies saved to output_policies/
- Full results saved to eval_results.json

### File structure required
```
your_folder/
├── agent.py
├── tools.py
├── criteria.py
├── eval.py
├── policies/
│   ├── weak_1.json ... weak_4.json
│   ├── strong_1.json ... strong_3.json
│   ├── edge_1.json
│   └── score_3.json
```

---

## Part 3 — GCP IAM Policy Classification (Bonus)

### No additional dependencies beyond Part 2.

### How to run

```bash
# Make sure GROQ_API_KEY is still set (same as Part 2)
python3 gcp_demo.py
```

### Expected output
- GCP to AWS translation example
- Classification table (6 GCP policies)
- 100% agreement rate
- Detailed findings per policy
- Results saved to gcp_eval_results.json

### File structure required
```
your_folder/
├── agent.py
├── tools.py
├── criteria.py
├── gcp_adapter.py
├── gcp_classifier.py
├── gcp_demo.py
├── gcp_policies/
│   ├── gcp_weak_1.json ... gcp_weak_3.json
│   ├── gcp_strong_1.json, gcp_strong_2.json
│   └── gcp_edge_1.json
```

---

## Quick Reference

| Part | Command | Key dependency |
|------|---------|----------------|
| Part 1 — exploit demo | `python3 attack_demo.py` | none |
| Part 1 — unit tests | `python3 -m unittest test.py -v` | none |
| Part 2 — eval | `python3 eval.py` | groq, GROQ_API_KEY |
| Part 3 — GCP bonus | `python3 gcp_demo.py` | groq, GROQ_API_KEY |

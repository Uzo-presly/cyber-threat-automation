# Cyber Threat Automation

A Python-based cybersecurity automation project that collects recent
vulnerability information, correlates vulnerabilities with the CISA Known
Exploited Vulnerabilities (KEV) catalog, calculates deterministic priority,
uses Gemini AI to generate security analysis, creates threat reports, and
delivers reports through email.

---

## Project Overview

The goal of this project is to automate part of the vulnerability-analysis
workflow that a cybersecurity analyst might otherwise perform manually.

Instead of manually searching for vulnerabilities, checking their severity,
checking whether they are known to be exploited, analyzing their potential
impact, writing a report, and sending that report by email, this project
connects these activities into a repeatable Python workflow.

The current implementation focuses on vulnerability intelligence and
prioritization.

---

## Current Workflow

The working vulnerability-analysis pipeline follows this general flow:

    NVD
     |
     v
    CVE Collection
     |
     v
    CVSS / Severity Extraction
     |
     v
    Priority Scoring
     |
     +----------------------+
     |                      |
     v                      v
    CISA KEV             Priority
    Correlation           Decision
     |                      |
     +----------+-----------+
                |
                v
          Gemini AI Analysis
                |
                v
          Threat Report
                |
                v
          Email Delivery


The system combines deterministic security scoring with AI-generated
analysis.

The deterministic scoring provides a consistent prioritization mechanism,
while Gemini provides natural-language analysis that helps explain the
security significance of a vulnerability.

---

## Main Components

### 1. NVD Vulnerability Collection

`src/vulnerabilities.py`

Collects vulnerability information from the National Vulnerability Database
(NVD).

The collector extracts information such as:

- CVE identifier
- Publication date
- CVSS version
- CVSS score
- Severity
- Vulnerability description
- NVD reference link

---

### 2. CVSS-Based Priority Scoring

`src/scorer.py`

The project uses CVSS information as one of the main inputs for determining
vulnerability priority.

The scoring system converts severity information into deterministic priority
points and labels.

The project also applies additional priority when a vulnerability is found
in the CISA KEV catalog.

This allows the automation to distinguish between:

- severity of a vulnerability
- evidence that the vulnerability is known to be exploited

---

### 3. CISA KEV Correlation

`src/kev.py`

Downloads the CISA Known Exploited Vulnerabilities (KEV) catalog and creates
a lookup structure that can be used to determine whether a CVE is present in
the catalog.

A vulnerability appearing in the KEV catalog is treated as an important
additional risk signal during prioritization.

---

### 4. Gemini AI Security Analysis

`src/summarizer.py`

Uses Google's Gemini API to generate a structured security analysis for each
selected vulnerability.

The analysis is designed to explain:

1. Executive Summary
2. Potential Impact
3. Who Should Care
4. Why the Automation Prioritized It This Way
5. Defensive Actions
6. Analyst Note
7. Step-by-Step Proof of Concept
8. Incident Response Statement

The proof-of-concept section is intended for authorized security testing and
laboratory environments.

The AI prompt also instructs the model not to invent vulnerability details
that are not available from the supplied information.

---

### 5. Threat Report Generation

`src/report.py`

Converts the analyzed vulnerability information into a structured threat
report.

Reports contain information such as:

- CVE information
- CVSS information
- Severity
- KEV status
- Priority
- Vulnerability description
- AI-generated analysis

Generated reports are stored locally and are excluded from Git using
`.gitignore`.

---

### 6. Email Delivery

`src/email_sender.py`

Sends generated threat reports through email.

Credentials are retrieved from environment variables rather than being
hard-coded into the source code.

The project therefore keeps credentials outside the Git repository.

---

## Project Structure

```text
cyber-threat-automation/
|
├── cyber_threat_automation.py
├── README.md
├── requirements.txt
├── .gitignore
|
└── src/
    ├── __init__.py
    ├── email_sender.py
    ├── kev.py
    ├── news.py
    ├── report.py
    ├── scorer.py
    ├── summarizer.py
    └── vulnerabilities.py
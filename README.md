# MailSentinel

### AI-Powered Email Threat Detection, Geolocation & Forensic Intelligence Platform

**Smart India Hackathon 2026**
<br>
**Team Name:** Signal-X
<br>
**Problem Statement ID:** 26106
<br>
**Theme:** Blockchain & CyberSecurity
<br>
**Category:** Software

---

## Overview

**MailSentinel** is an AI-powered email threat detection and forensic intelligence platform designed to go beyond simple phishing classification.

Instead of treating an email as an isolated **safe/phishing** decision, MailSentinel combines **content analysis, email authentication, infrastructure intelligence, reputation signals, and historical correlation** to build an evidence-based assessment of the threat.

The platform supports both **`.eml` investigation** and **Gmail-based analysis**, providing a centralized investigation workflow through a web dashboard and a Gmail add-on.

### Core Idea

> **Detection → Evidence → Correlation → Investigation**

MailSentinel aims to answer not only:

**“Is this email malicious?”**

but also:

**“Why is it suspicious, what evidence supports the verdict, what infrastructure is involved, and is it connected to previously observed threats?”**

---

# Why MailSentinel?

Traditional email security systems often focus primarily on detecting an individual malicious email. This creates several investigation challenges:

* **Isolated incident blindness** — related attacks may be treated as independent events.
* **Black-box verdicts** — users may receive a threat score without understanding the evidence behind it.
* **Manual forensic effort** — investigators often have to inspect headers, URLs, domains, IPs and infrastructure separately.
* **Limited campaign visibility** — connections between seemingly different emails may remain hidden.

MailSentinel addresses these challenges by combining multiple forensic signals into a single investigation pipeline.

---

# How It Works

```text
                         Email
                           │
              ┌────────────┴────────────┐
              │                         │
         .eml Upload              Gmail Add-on
              │                         │
              └────────────┬────────────┘
                           │
                           ▼
              ┌──────────────────────────┐
              │     MailSentinel API     │
              └────────────┬─────────────┘
                           │
       ┌───────────────────┼───────────────────┐
       │                   │                   │
       ▼                   ▼                   ▼
   Content            Headers &         Infrastructure
   Analysis          Authentication       Intelligence
       │                   │                   │
       └───────────────────┼───────────────────┘
                           │
                           ▼
                  Reputation & Exposure
                           │
                           ▼
                   Attack Correlation
                           │
                           ▼
               Evidence & Risk Assessment
                           │
                 ┌─────────┴─────────┐
                 │                   │
                 ▼                   ▼
          React Dashboard       Gmail Add-on
```

---

# Five-Engine Forensic Pipeline

MailSentinel's analysis is organized into five complementary investigation engines.

## 1. Content Threat Detection

The content analysis engine evaluates the textual and structural characteristics of an email to identify phishing and malicious-content patterns.

It combines:

* TF-IDF text features
* Structural email features
* A **Calibrated Linear SVM** phishing classifier
* Attachment and image inspection
* OCR and QR-code extraction

The machine-learning classifier produces a calibrated phishing probability, which becomes one of the signals used in the overall threat assessment.

The engine is part of a larger forensic pipeline rather than acting as the sole decision-maker.

---

## 2. Header & Authentication Analysis

The header analysis engine examines email metadata, sender information and authentication results to identify spoofing and delivery anomalies.

It analyzes signals including:

* `From`
* `Reply-To`
* `Return-Path`
* `Received` chain
* Sender and domain information
* SPF
* DKIM
* DMARC
* Message-ID and related header characteristics

These signals help identify authentication failures, sender inconsistencies and suspicious mail-routing behaviour.

---

## 3. Infrastructure Intelligence

The infrastructure intelligence engine investigates the technical infrastructure associated with domains, URLs and IP addresses.

Analysis can include:

* Domain and IP relationships
* DNS records
* WHOIS / RDAP information
* ASN information
* TLS information
* JARM fingerprints
* Mail-server infrastructure
* Domain and infrastructure fingerprints

This layer helps determine whether the infrastructure associated with an email exhibits suspicious or previously observed characteristics.

---

## 4. Reputation & Exposure Analysis

MailSentinel enriches extracted domains and IP addresses using external reputation and threat-intelligence sources.

Depending on configuration and availability, the platform can use sources such as:

* AbuseIPDB
* PhishTank
* Spamhaus DBL
* Shodan InternetDB
* IP and geolocation intelligence
* Other domain/IP reputation information

These signals provide additional context about the reputation, exposure and observed history of the infrastructure involved.

---

## 5. Attack Graph & Correlation

MailSentinel goes beyond analyzing a single email by correlating indicators and infrastructure observed across investigations.

Relationships can be established through:

* Domains
* IP addresses
* URLs
* Nameservers
* Mail servers
* ASNs
* Infrastructure fingerprints
* JARM fingerprints
* Structural and style fingerprints
* Other extracted indicators

This historical correlation layer can reveal relationships between seemingly unrelated emails and help identify broader attack infrastructure or campaigns.

---

# Evidence & Explainable Risk Assessment

The outputs from the analysis engines are combined into an overall evidence-based threat assessment.

## Overall Risk Score

MailSentinel generates a unified **0–100 risk score** from the combined analysis signals.

## Threat Verdict

The resulting risk assessment is categorized into levels such as:

* **Low**
* **Medium**
* **High**

## Threat Contribution

To make the assessment understandable without exposing low-level model internals, MailSentinel provides a high-level **Threat Contribution** breakdown.

The user-facing contribution categories are:

1. **Content / ML Analysis**
2. **URL Analysis**
3. **Email Authentication**
4. **Infrastructure / Domain Reputation**
5. **QR / OCR Analysis**
6. **Attachment Analysis**

The backend calculates the contribution percentages from the available evidence and normalizes them into an interpretable breakdown.

This provides investigators with a concise explanation of **which evidence categories contributed to the overall assessment**.

---

# Key Innovation

MailSentinel is designed around **forensic investigation rather than classification alone**.

### From Individual Detection → Campaign-Level Intelligence

A suspicious email does not necessarily represent an isolated event. Shared infrastructure, domains, IPs and fingerprints can reveal connections with previously investigated incidents.

### From Black-Box Verdicts → Evidence-Based Assessment

Instead of presenting only a phishing label, MailSentinel surfaces the major evidence categories contributing to the assessment.

### From Manual Investigation → Automated Intelligence

Content inspection, authentication analysis, infrastructure enrichment, reputation checks and correlation are brought together into a single workflow.

### From Email → Full Threat Context

MailSentinel analyzes an email as a complete artifact:

**Content + Headers + URLs + Attachments + Infrastructure + Reputation + Historical Evidence**

---

# System Architecture

```text
                         ┌──────────────────┐
                         │      Email       │
                         └────────┬─────────┘
                                  │
                 ┌────────────────┴────────────────┐
                 │                                 │
          .eml Upload                         Gmail Add-on
                 │                                 │
                 └────────────────┬────────────────┘
                                  │
                                  ▼
                       ┌─────────────────────┐
                       │    Flask REST API   │
                       └──────────┬──────────┘
                                  │
          ┌───────────────────────┼───────────────────────┐
          │                       │                       │
          ▼                       ▼                       ▼
   Content Analysis       Header & Authentication   Infrastructure
          │                       │                  Intelligence
          └───────────────────────┼───────────────────────┘
                                  │
                                  ▼
                       Reputation & Exposure
                                  │
                                  ▼
                       Attack Correlation
                                  │
                                  ▼
                    Evidence & Risk Assessment
                                  │
                    ┌─────────────┴─────────────┐
                    │                           │
                    ▼                           ▼
             React Dashboard              PostgreSQL
                    │
                    ▼
            Investigation Results
```

---

# Analysis Workflow

A typical investigation follows this process:

```text
1. Email received
        ↓
2. .eml uploaded / Gmail scan initiated
        ↓
3. Email content extracted
        ↓
4. Headers and authentication analyzed
        ↓
5. URLs, domains and IPs extracted
        ↓
6. Infrastructure & reputation intelligence collected
        ↓
7. Attachments / images inspected
        ↓
8. Indicators correlated with historical observations
        ↓
9. Evidence combined
        ↓
10. Risk score + verdict generated
        ↓
11. Threat Contribution calculated
        ↓
12. Investigation results displayed
```

---

# Web Dashboard

The React-based dashboard provides an investigation-oriented interface for analyzing suspicious emails.

It can present:

* Overall threat verdict
* Risk score
* Threat Contribution breakdown
* Email metadata
* Header and authentication results
* Extracted URLs and domains
* Infrastructure information
* Reputation results
* OCR / QR findings
* Attachment analysis
* Historical correlation results
* Supporting forensic evidence

The dashboard is intended for **deeper investigation and forensic analysis**.

---

# Gmail Add-on

MailSentinel can also be accessed directly from Gmail through a Google Apps Script-based add-on.

The add-on provides a lightweight **first-level triage experience**, including:

* Email scanning directly from Gmail
* Pre-scan interface
* Investigation results
* Backend-generated threat verdict
* Risk score
* Authentication results
* Infrastructure risk information
* Domain intelligence
* Selected security findings
* Link to the full web investigation

The add-on is intentionally focused on quick investigation. Detailed forensic analysis is available through the **MailSentinel web dashboard**.

---

# Data Storage & Historical Intelligence

PostgreSQL is used to store investigation data and extracted intelligence.

Stored information can include:

* Email metadata
* Analysis results
* Threat scores
* Extracted indicators
* Infrastructure intelligence
* Correlation information
* Threat Contribution results
* Investigation records

This historical evidence base allows newly observed indicators to be compared with previously analyzed observations.

---

# Tech Stack

## Backend

* Python
* Flask
* PostgreSQL
* psycopg2
* scikit-learn
* NetworkX
* Authlib

## Machine Learning

* TF-IDF
* Calibrated Linear SVM
* Structural email features

## Threat Intelligence & Forensics

* WHOIS / RDAP
* DNS
* TLS analysis
* JARM
* AbuseIPDB
* Shodan InternetDB
* PhishTank
* Spamhaus DBL
* IP / geolocation intelligence
* OCR
* QR-code extraction

## Frontend

* React
* React Router
* Vite

## Gmail Integration

* Google Apps Script
* Gmail Add-on APIs

## Database

* PostgreSQL

---

# Current Status

MailSentinel currently provides an end-to-end prototype covering:

* `.eml` email ingestion
* Machine-learning based content detection
* Header and authentication analysis
* URL and domain analysis
* Infrastructure intelligence
* Reputation enrichment
* OCR and QR-code analysis
* Attachment analysis
* Historical indicator correlation
* Evidence-based risk assessment
* Threat Contribution analysis
* PostgreSQL-backed investigation storage
* React investigation dashboard
* Gmail add-on integration

The system is designed as a working prototype. Some external intelligence sources depend on provider configuration, API availability and rate limits.

---

# Future Scope

Potential future improvements include:

* Per-user and organization-level correlation
* Larger and continuously updated threat-intelligence datasets
* Advanced campaign clustering
* Improved attack-graph visualization
* Additional email-provider integrations
* Automated forensic report generation
* Expanded attachment and document analysis
* Real-time threat-intelligence feeds
* Privacy-preserving deployment options
* Scalable cloud deployment for larger organizations

---

# Impact

### Individual Users

Helps users understand whether a suspicious email is dangerous and provides supporting evidence behind the assessment.

### Organizations

Provides a centralized investigation workflow and historical intelligence for repeated phishing attempts.

### Security & Forensics Teams

Reduces manual investigation effort by combining multiple forensic signals into a single platform.

### Broader Cybersecurity

Moves email security from isolated phishing detection toward **campaign- and infrastructure-level threat intelligence**.

---

# Team

### Team Signal-X

* Anshika Pandey
* Aanya Garg
* Adya Singh
* Aiza Nabiha
* Arushi Pandey
* Asmi

---

# Project Links

**Prototype:** `https://mail-sentinel-one.vercel.app/`

---

## MailSentinel

> **Detect the threat. Understand the evidence. Discover the campaign.**

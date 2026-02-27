# Final Project Report: AI-Driven Threat Intelligence Platform

_State of the System: Phases 1 through 3_

---

## 1. Executive Summary

Modern cybersecurity teams face an impossible volume of data. Every day, global threat intelligence feeds publish hundreds of thousands of individual indicators—malicious IP addresses, compromised domains, virus signatures, and software vulnerabilities. For a human analyst, this flood of disconnected data creates "alert fatigue." It is impossible to manually process this volume, let alone understand how an IP address from one report might be linked to a phishing domain from another.

This project was initiated to solve that exact problem. We have built an **Autonomous AI Threat Intelligence Platform**. Instead of simply collecting data, this system acts as a digital analyst. It automatically ingests threat reports, uses Artificial Intelligence to read and understand them, maps out hidden relationships between attackers, and ultimately discovers coordinated cyberattack campaigns before they strike.

This report details the three foundational phases of the platform that have been successfully deployed.

---

## 2. Phase 1: Automated Data Collection & AI Understanding

### What We Built

The foundation of any intelligence system is its data. In Phase 1, we built an automated extraction engine that connects to global, high-value threat feeds (such as the US Government's CISA Known Exploited Vulnerabilities catalog).

Crucially, we did not just build a web scraper. We integrated a **Local Large Language Model (LLM)**. When a raw text report is downloaded, the AI model reads the English text, understands the context of the attack, and extracts the specific "Indicators of Compromise" (IOCs).

### Why We Built It

Raw threat reports are written for humans to read, making them difficult for traditional software to parse. A standard script might miss critical context (e.g., extracting an IP address that belongs to a victim rather than the attacker). By using an AI model to read the reports, we ensure high-fidelity data extraction. Furthermore, by running the AI model _locally_ (via Ollama), we guarantee zero data leakage; sensitive threat intelligence is never sent to third-party cloud providers like OpenAI.

---

## 3. Phase 2: The Threat Knowledge Graph

### What We Built

Extracting the data is only the first step; the true value lies in connecting it. In Phase 2, we architected a **Knowledge Graph**.

A Knowledge Graph is a specialized database designed to map relationships rather than just store rows of data. It operates like a digital detective's string board. When the AI from Phase 1 finds that "IP Address A" and "Domain B" are mentioned in the same ransomware report, the Knowledge Graph creates a mathematical link between them.

The current live Knowledge Graph holds over **220,000 unique threat nodes** and maps over **317,000 relationships** between them.

### Why We Built It

Attackers do not operate in isolation; they build infrastructure. A hacker might use one IP to scan a firewall, a separate domain to host malware, and an email address to send the phishing link. If a security system looks at these indicators individually, they appear as low-level background noise.

By graphing the relationships, our platform can "walk" the connections mathematically. If a company detects a suspicious IP, the Knowledge Graph instantly reveals every other IP, domain, and vulnerability that the attacker is known to associate with, exposing their entire toolkit instantly.

---

## 4. Phase 3: Temporal Campaign Detection

### What We Built

Phase 3 is the culmination of the platform's analytical power. We implemented a mathematical engine specifically, the **Louvain Community Detection Algorithm** directly on top of the Knowledge Graph.

The algorithm analyzes the hundreds of thousands of connections simultaneously to find "communities"—tightly connected clusters of threat indicators that frequently interact.

Once a cluster is found, the system enriches it with time data (when the threat was first and last seen) and severity scores to officially declare an active **Threat Campaign**. The system then saves these campaigns and exposes them via a secure API to our SOC Command Dashboard. In recent live environment testing, the engine successfully condensed 220,000 raw indicators into **46 focused, highly confident attack campaigns**.

### Why We Built It

The Knowledge Graph proves _how_ things are connected, but human analysts still have to know where to look. Phase 3 flips the paradigm from reactive to proactive.

Instead of waiting for an analyst to search for a specific IP address, the Campaign Detection engine automatically finds the hacker groups hiding in the data. It answers the most critical question in a Security Operations Center: **"What should we be paying attention to right now?"**

By presenting 46 concrete campaigns instead of 220,000 isolated alerts, we give security teams the exact context they need to block an entire coordinated attack at once, rather than playing whack-a-mole with individual IP addresses.

---

## 5. Engineering Reliability and Architecture

To ensure this system operates at enterprise grade, several key engineering decisions were implemented:

- **Decoupled Architecture**: The system runs in isolated Docker containers (Database, AI Engine, Scheduler, Backend API, and Frontend Dashboard). If one component fails, the rest of the system remains operational.
- **Fully Automated Lifecycle**: The system is completely autonomous. A background scheduler triggers the data collection, passes it to the AI for extraction, updates the Knowledge Graph, and runs the Campaign Detection engine every 30 minutes without human intervention.
- **Rigorous Verification**: Over 58 automated unit tests run continuously against the codebase, verifying everything from the AI's extraction accuracy to the mathematical correctness of the graph clustering.

## 6. Conclusion

Phases 1 through 3 have successfully transformed a sprawling, chaotic environment of global threat data into a structured, relational, and highly actionable intelligence engine. The system automatically reads reports, connects the dots, and spots the campaigns.

With this foundation complete, the platform is now ready for its next evolutionary step: **Agentic Predictive Threat Forecasting**, where we will use the mapped campaigns to predict an attacker's future movements before they happen.

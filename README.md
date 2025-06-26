# 🔬 Automation and Security Experimentation Repository

This repository provides a structured framework for experimenting with:

- 🧠 LLM-based taxonomy of smells and rule generation for configuration management tools  
- 🔐 Snyk-based vulnerability scanning automation  
- 📊 Dataset scraping and CI/CD integration (Jenkins) and Snyk analysis

---

## 📁 Repository Structure

experiments/
│
├── LLM-experiments/ # LLM-based taxonomy of security smells and rule generation
│ ├── ansible_rule_generation.py
│ ├── puppet_rules_generation.py
│ ├── salt_rule_generation.py
│ ├── terraform_rules_generation.py
│ ├── smell_category_valid.py
│
├── Snyk-experiments/ # Git cloning using commit_url from dataset and Snyk analysis of scripts
│ ├── git_clone.py
│ ├── snykanalyse.py
│
├── dataset-scrapping/ # Jenkins automation for dataset collection
│ ├── Jenkinsfile
│
└── results/ # Outputs organized by experiment type
├── LLM-experiments/
├── Snyk-experiments/
└── dataset-scrapping/


---

## 🚀 Features

- **LLM-based Taxonomy of Security Smells**: Use of LLM to derive security smell categories from IaC smelly code snippets.
- **Rule Generation Automation**: Generate rules for tools like Ansible, Puppet, Salt, and Terraform using Python + LLMs.
- **Snyk Scanning**: Automate scanning of cloned repositories using Snyk CLI.
- **Data Pipeline**: Use Jenkins to manage and schedule scraping tasks.
- **Results Tracking**: Keep experiment outputs cleanly organized under `results/`.

---

## 📦 Requirements

- Python 3.x
- `snyk` CLI
- Jenkins (for CI tasks)
- Required Python packages: `pandas`, `requests`, etc.
- API Key from GPT-3.5-turbo
- Token from from GitHub for dataset scrapping script
- installation of ansible-lint, terrascan, rubocop, and salt-lint

---


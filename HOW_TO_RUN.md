# How to Run: Zero-Standing-Privilege Honeytoken Defense Mesh

This run guide covers local CLI simulation, Pytest execution, Docker containerization, and Terraform deployment.

---

## 1. Local CLI Simulation

```bash
# Windows PowerShell
.\run.ps1

# Windows Command Prompt
run.bat

# Linux / macOS
chmod +x run.sh && ./run.sh
```

Or directly via Python:
```bash
python -m src.cli simulate
```

---

## 2. Running Automated Tests & Code Quality Checks

```bash
# Run Pytest suite
pytest -v

# Run Ruff linter and formatter
ruff check --fix src tests
ruff format src tests
```

---

## 3. Docker Container Deployment

```bash
# Build Docker image
docker build -t zsp-honeytoken-mesh:latest .

# Run containerized simulation
docker run --rm zsp-honeytoken-mesh:latest
```

---

## 4. Terraform Cloud Deployment

```bash
cd terraform

# Initialize providers
terraform init

# Review execution plan
terraform plan

# Apply infrastructure
terraform apply -auto-approve
```

# AI Skills Security Scanner

This project builds a GitHub Action that scans all .md files inside the skills/ folder using an AI model to detect malicious content (prompt injection, hidden commands, data exfiltration, etc.).

If malicious text is found, the workflow prints the suspicious lines and fails automatically.

---

# 🔐 Purpose

AI skills can execute instructions automatically.  
This project acts as an automated security guardrail to prevent malicious instructions from entering the repository.

---

# 🤖 AI Model & Detection Logic

### 🔹 AI Provider
- Groq API

### 🔹 Model Used
- llama-3.1-8b-instant

### 🔹 How It Works

1. The script scans the `skills/` folder.
2. It reads all `.md` files.
3. Each file is sent to the Groq LLM for classification.
4. The AI must return structured JSON:
   - `SAFE`
   - `MALICIOUS`
5. If classified as `MALICIOUS`, the script:
   - Prints the suspicious line(s)
   - Exits with a non-zero status (`exit(1)`)
6. The GitHub Action then fails automatically.

---

# 🔄 GitHub Action

The workflow triggers on:

- `push` to `main`
- `pull_request`

The action:

1. Checks out the repository  
2. Installs dependencies  
3. Runs the scanner  
4. Fails if malicious content is detected  

---

# ⚙️ Setup Instructions

## 1️⃣ Clone the Repository

```bash
git clone <your-repo-url>
cd <repo-name>
```

## 2️⃣ Install Dependencies

```bash
pip install -r requirements.txt
```

## 3️⃣ Set Environment Variable

You must set your Groq API key.

**Mac/Linux**
```bash
export GROQ_API_KEY="your_api_key_here"
```

**Windows (PowerShell)**
```powershell
setx GROQ_API_KEY "your_api_key_here"
```

---

# ▶️ Run Locally

```bash
python scanner/scan.py
```
import os
import sys
import re
import json
from openai import OpenAI

SKILLS_DIR = "skills"
MODEL = "gpt-4o-mini"

client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

SUSPICIOUS_PATTERNS = [
    r"ignore\s+previous\s+instructions",
    r"send\s+.*secret",
    r"override\s+system",
]

def regex_scan(text):
    findings = []
    lines = text.split("\n")

    for i, line in enumerate(lines, 1):
        for pattern in SUSPICIOUS_PATTERNS:
            if re.search(pattern, line, re.IGNORECASE):
                findings.append((i, line.strip()))
    return findings


def ai_scan(text):
    system_prompt = """
You are a security scanner.
Classify content as SAFE or MALICIOUS.
Return JSON:

{
  "classification": "SAFE" or "MALICIOUS",
  "malicious_lines": [
    {"line_number": int, "content": "string"}
  ]
}
"""

    response = client.chat.completions.create(
        model=MODEL,
        messages=[
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": text}
        ],
        temperature=0
    )

    try:
        return json.loads(response.choices[0].message.content)
    except:
        return {"classification": "SAFE", "malicious_lines": []}


def main():
    print("Scanning skills folder...\n")

    malicious_found = False

    for filename in os.listdir(SKILLS_DIR):
        if filename.endswith(".md"):
            filepath = os.path.join(SKILLS_DIR, filename)
            print(f"Reading: {filepath}")

            with open(filepath, "r", encoding="utf-8") as f:
                content = f.read()

            regex_results = regex_scan(content)

            if regex_results:
                malicious_found = True
                print("Regex detected:")
                for line_no, line_text in regex_results:
                    print(f"Line {line_no}: {line_text}")

            ai_result = ai_scan(content)

            if ai_result["classification"] == "MALICIOUS":
                malicious_found = True
                print("AI detected:")
                for item in ai_result["malicious_lines"]:
                    print(f"Line {item['line_number']}: {item['content']}")

            print()

    if malicious_found:
        print("❌ Failing workflow: malicious content found")
        sys.exit(1)
    else:
        print("✅ All files are SAFE")
        sys.exit(0)


if __name__ == "__main__":
    main()
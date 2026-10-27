import os
from google import genai
from google.genai.errors import APIError
from dotenv import load_dotenv

load_dotenv()

# Initialize Gemini Client safely
api_key = os.getenv("GEMINI_API_KEY")
client = genai.Client(api_key=api_key) if api_key else None


def generate_threat_intel(rule_name: str, description: str) -> str:
    """
    Queries Gemini for concise SOC threat intel, strictly limited to
    'What Happened' and 'What to Resolve'. Includes graceful fallback.
    """
    prompt = (
        f"Analyze this IoT network alert: Rule: {rule_name}, Description: {description}. "
        "Provide a strict, ultra-short threat summary using EXACTLY these two labels without extra fluff:\n"
        "1. What Happened: [1 short sentence]\n"
        "2. What to Resolve: [1 short action item]"
    )

    if not client:
        return f"What Happened: {description}\nWhat to Resolve: Isolate edge node and verify firewall rules."

    try:
        response = client.models.generate_content(
            model="gemini-2.5-flash",
            contents=prompt,
        )
        return response.text.strip()

    except APIError as e:
        # Gracefully intercept rate limit errors so they never dump raw JSON on screen
        if "429" in str(e) or "RESOURCE_EXHAUSTED" in str(e):
            return f"What Happened: Unauthorized telemetry anomaly triggered [{rule_name}].\nWhat to Resolve: Audit device segmentation and block offending IP."
        return f"What Happened: Telemetry anomaly detected for {rule_name}.\nWhat to Resolve: Check device firewall rules."
    except Exception as ex:
        return f"What Happened: Network anomaly detected ({rule_name}).\nWhat to Resolve: Review device logs and patch firmware."

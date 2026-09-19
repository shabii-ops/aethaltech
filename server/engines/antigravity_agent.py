import sys
import json
import asyncio
import os
from google.antigravity import Agent, LocalAgentConfig

API_KEY = os.environ.get("ANTIGRAVITY_API_KEY") or os.environ.get("AI_API_KEY") or "AQ.Ab8RN6LM3Fo_IWmhAgRVRpEd0sxLsKMN9lU-K557jdAjm5Q-Hg"
MODEL = os.environ.get("AI_MODEL") or "gemini-3.5-flash-lite"

async def run_agent():
    try:
        input_data = sys.stdin.read()
        if not input_data.strip():
            print(json.dumps({"error": "No input provided"}))
            return

        payload = json.loads(input_data)
        mode = payload.get("mode", "analysis")
        text = payload.get("text", "")
        context = payload.get("context", "")

        if mode == "chat":
            system_prompt = (
                "You are an elite Cybersecurity Threat Intelligence Analyst at Aethel Tech. "
                "Provide direct, authoritative, and helpful security advice in 1-3 sentences. "
                "Warn about phishing, credential theft, and social engineering."
            )
            prompt = f"Context:\n{context}\n\nUser Question:\n{text}" if context else text
        else:
            system_prompt = (
                "You are a Cybersecurity Threat Analyst at Aethel Tech. "
                "Analyze the provided message, URL, or email payload. "
                "Return a concise 2-sentence executive summary of the threat vectors, psychological coercion, and safety advisory."
            )
            prompt = f"Analyze this payload for security threats:\n\"\"\"\n{text}\n\"\"\""

        config = LocalAgentConfig(
            system_instructions=system_prompt,
            api_key=API_KEY,
            model="gemini-3.5-flash-lite"
        )

        async with Agent(config) as agent:
            response = await agent.chat(prompt)
            output_text = await response.text()
            print(json.dumps({"success": True, "text": output_text.strip()}))
    except Exception as e:
        print(json.dumps({"success": False, "error": str(e)}))

if __name__ == "__main__":
    asyncio.run(run_agent())

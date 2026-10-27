"""Transcribe a call recording or voice note with Whisper on Groq.

Scam calls are often in Hindi or Hinglish; whisper-large-v3 handles both.
"""

from __future__ import annotations

import os

WHISPER_MODEL = os.environ.get("SCAMSHIELD_WHISPER", "whisper-large-v3")


def transcribe(file_bytes: bytes, filename: str) -> str:
    if not os.environ.get("GROQ_API_KEY"):
        raise RuntimeError("Call transcription needs a GROQ_API_KEY (free at console.groq.com).")
    from groq import Groq

    client = Groq(api_key=os.environ["GROQ_API_KEY"])
    result = client.audio.transcriptions.create(
        file=(filename, file_bytes),
        model=WHISPER_MODEL,
        temperature=0.0,
        response_format="text",
    )
    return result if isinstance(result, str) else getattr(result, "text", str(result))

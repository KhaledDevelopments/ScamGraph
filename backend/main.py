from pathlib import Path

from dotenv import load_dotenv
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field, field_validator

from services.analysis import analyze_content
from providers import gemini

# Load local keys while keeping existing environment variables authoritative.
load_dotenv(Path(__file__).with_name(".env"), override=False)

app = FastAPI()

# Allow requests from the local Vite frontend during development.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
    allow_methods=["POST"],
    allow_headers=["Content-Type"],
)


class AnalyzeRequest(BaseModel):
    content: str = Field(min_length=1, strict=True)

    @field_validator("content")
    @classmethod
    def reject_blank_content(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("Content must contain more than whitespace")
        return value


class ExplainRequest(BaseModel):
    content: str = Field(min_length=1, strict=True)
    assessment: dict
    indicators: dict


@app.get("/")
def read_root():
    return {"Hello": "World"}


@app.get("/items/{item_id}")
def read_item(item_id: int, q: str | None = None):
    return {"item_id": item_id, "q": q}


@app.post("/analyze")
def analyze(request: AnalyzeRequest) -> dict:
    """Extract indicators and enrich the first URL with existing VT evidence."""
    return {
        "message": "Content received",
        "content": request.content,
        **analyze_content(request.content),
    }


@app.post("/explain")
def explain(request: ExplainRequest) -> dict:
    """Generate a plain-English explanation of an already-computed assessment."""
    return gemini.explain(request.content, request.assessment, request.indicators)
"""
Local AI Model Backend - Runtime Abstraction

Provides pluggable abstraction for local model inference:
- llama.cpp/GGUF support
- Ollama local server support
- Auto-detection and fallback
- No cloud API dependency
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Optional, List, Dict, Any
import logging
import subprocess
import json
from pathlib import Path

logger = logging.getLogger(__name__)


@dataclass
class LocalModelInfo:
    """Information about a local model."""
    name: str
    path: str
    size_gb: float
    backend: str  # "llama.cpp", "ollama", "gguf"
    context_length: int
    quantization: str  # "Q4", "Q5", "Q8", "fp16", etc.
    loaded: bool = False


@dataclass
class LocalInferenceRequest:
    """Request for local model inference."""
    prompt: str
    max_tokens: int = 500
    temperature: float = 0.7
    top_p: float = 0.95
    top_k: int = 40
    repeat_penalty: float = 1.1
    system_prompt: Optional[str] = None


@dataclass
class LocalInferenceResponse:
    """Response from local model."""
    text: str
    tokens_used: int
    stop_reason: str  # "max_tokens", "stop_token", "error"
    error: Optional[str] = None
    latency_ms: int = 0


class LocalModelBackend(ABC):
    """Abstract base for local model inference backends."""

    @abstractmethod
    def initialize(self) -> bool:
        """Initialize backend and load model."""
        pass

    @abstractmethod
    def is_available(self) -> bool:
        """Check if backend is available."""
        pass

    @abstractmethod
    def get_model_info(self) -> Optional[LocalModelInfo]:
        """Get information about loaded model."""
        pass

    @abstractmethod
    def infer(self, request: LocalInferenceRequest) -> LocalInferenceResponse:
        """Run inference."""
        pass

    @abstractmethod
    def shutdown(self) -> None:
        """Shutdown backend."""
        pass


class OllamaBackend(LocalModelBackend):
    """Ollama local model server backend."""

    def __init__(self, host: str = "127.0.0.1", port: int = 11434, model: str = "neural-chat"):
        self.host = host
        self.port = port
        self.model = model
        self.base_url = f"http://{host}:{port}"
        self.model_info: Optional[LocalModelInfo] = None
        self.initialized = False

    def initialize(self) -> bool:
        """Initialize Ollama backend."""
        try:
            if not self.is_available():
                logger.warning(f"Ollama server not available at {self.base_url}")
                return False

            # Try to load model
            self._pull_model_if_needed()
            self.initialized = True
            logger.info(f"Ollama backend initialized with model: {self.model}")
            return True
        except Exception as e:
            logger.error(f"Failed to initialize Ollama backend: {e}")
            return False

    def is_available(self) -> bool:
        """Check if Ollama server is running."""
        try:
            import requests
            resp = requests.get(f"{self.base_url}/api/tags", timeout=2)
            return resp.status_code == 200
        except:
            return False

    def get_model_info(self) -> Optional[LocalModelInfo]:
        """Get model information from Ollama."""
        if not self.is_available():
            return None

        try:
            import requests
            resp = requests.get(f"{self.base_url}/api/show", 
                              params={"name": self.model}, timeout=5)
            if resp.status_code == 200:
                data = resp.json()
                return LocalModelInfo(
                    name=self.model,
                    path="ollama://local",
                    size_gb=data.get("details", {}).get("parameter_size", "unknown"),
                    backend="ollama",
                    context_length=data.get("details", {}).get("context_length", 2048),
                    quantization=data.get("details", {}).get("quantization_level", "unknown"),
                    loaded=True
                )
        except Exception as e:
            logger.debug(f"Failed to get Ollama model info: {e}")
        return None

    def infer(self, request: LocalInferenceRequest) -> LocalInferenceResponse:
        """Run inference via Ollama."""
        try:
            import requests
            import time

            start_time = time.time()

            prompt = request.prompt
            if request.system_prompt:
                prompt = f"{request.system_prompt}\n\n{prompt}"

            payload = {
                "model": self.model,
                "prompt": prompt,
                "stream": False,
                "temperature": request.temperature,
                "top_p": request.top_p,
                "top_k": request.top_k,
                "num_predict": request.max_tokens,
            }

            resp = requests.post(
                f"{self.base_url}/api/generate",
                json=payload,
                timeout=60
            )

            if resp.status_code != 200:
                return LocalInferenceResponse(
                    text="",
                    tokens_used=0,
                    stop_reason="error",
                    error=f"Ollama error: {resp.status_code}"
                )

            data = resp.json()
            latency_ms = int((time.time() - start_time) * 1000)

            return LocalInferenceResponse(
                text=data.get("response", "").strip(),
                tokens_used=data.get("eval_count", 0),
                stop_reason="max_tokens" if data.get("done") else "stop_token",
                latency_ms=latency_ms
            )

        except Exception as e:
            logger.error(f"Ollama inference failed: {e}")
            return LocalInferenceResponse(
                text="",
                tokens_used=0,
                stop_reason="error",
                error=str(e)
            )

    def shutdown(self) -> None:
        """Shutdown Ollama backend."""
        self.initialized = False
        logger.info("Ollama backend shutdown")

    def _pull_model_if_needed(self) -> None:
        """Pull model from Ollama Hub if not available."""
        try:
            import requests
            # Check if model exists
            resp = requests.get(f"{self.base_url}/api/show",
                              params={"name": self.model}, timeout=5)
            if resp.status_code != 200:
                logger.info(f"Pulling model {self.model} from Ollama...")
                subprocess.run(
                    ["ollama", "pull", self.model],
                    timeout=300,
                    capture_output=True
                )
        except Exception as e:
            logger.debug(f"Failed to pull model: {e}")


class LlamaCppBackend(LocalModelBackend):
    """llama.cpp backend for GGUF models."""

    def __init__(self, model_path: Optional[str] = None):
        self.model_path = model_path
        self.process = None
        self.model_info: Optional[LocalModelInfo] = None
        self.initialized = False

    def initialize(self) -> bool:
        """Initialize llama.cpp backend."""
        try:
            if not self._find_model():
                logger.warning("No GGUF model found")
                return False

            self.initialized = True
            logger.info(f"llama.cpp backend initialized with: {self.model_path}")
            return True
        except Exception as e:
            logger.error(f"Failed to initialize llama.cpp backend: {e}")
            return False

    def is_available(self) -> bool:
        """Check if llama.cpp is available."""
        try:
            result = subprocess.run(
                ["llama-cpp-python", "--version"],
                capture_output=True,
                timeout=2
            )
            return result.returncode == 0
        except:
            return False

    def get_model_info(self) -> Optional[LocalModelInfo]:
        """Get GGUF model information."""
        if not self.model_path:
            return None

        try:
            path = Path(self.model_path)
            if path.exists():
                size_gb = path.stat().st_size / (1024**3)
                return LocalModelInfo(
                    name=path.name,
                    path=str(path),
                    size_gb=size_gb,
                    backend="llama.cpp",
                    context_length=2048,
                    quantization="GGUF",
                    loaded=self.initialized
                )
        except Exception as e:
            logger.debug(f"Failed to get model info: {e}")
        return None

    def infer(self, request: LocalInferenceRequest) -> LocalInferenceResponse:
        """Run inference via llama.cpp."""
        try:
            from llama_cpp import Llama
            import time

            start_time = time.time()

            if not self.model_path or not Path(self.model_path).exists():
                return LocalInferenceResponse(
                    text="",
                    tokens_used=0,
                    stop_reason="error",
                    error="Model file not found"
                )

            llm = Llama(
                model_path=self.model_path,
                n_ctx=2048,
                n_threads=4,
            )

            prompt = request.prompt
            if request.system_prompt:
                prompt = f"{request.system_prompt}\n\n{prompt}"

            response = llm(
                prompt,
                max_tokens=request.max_tokens,
                temperature=request.temperature,
                top_p=request.top_p,
                top_k=request.top_k,
                repeat_penalty=request.repeat_penalty,
            )

            latency_ms = int((time.time() - start_time) * 1000)

            return LocalInferenceResponse(
                text=response["choices"][0]["text"].strip(),
                tokens_used=response.get("usage", {}).get("completion_tokens", 0),
                stop_reason="max_tokens",
                latency_ms=latency_ms
            )

        except Exception as e:
            logger.error(f"llama.cpp inference failed: {e}")
            return LocalInferenceResponse(
                text="",
                tokens_used=0,
                stop_reason="error",
                error=str(e)
            )

    def shutdown(self) -> None:
        """Shutdown llama.cpp backend."""
        self.initialized = False
        logger.info("llama.cpp backend shutdown")

    def _find_model(self) -> bool:
        """Find available GGUF model."""
        if self.model_path and Path(self.model_path).exists():
            return True

        # Search common locations
        search_paths = [
            Path.home() / ".cache" / "huggingface" / "hub",
            Path.home() / "models",
            Path("/usr/local/share/models"),
            Path("./models"),
        ]

        for search_path in search_paths:
            if search_path.exists():
                for model_file in search_path.rglob("*.gguf"):
                    logger.info(f"Found GGUF model: {model_file}")
                    self.model_path = str(model_file)
                    return True

        return False


class LocalModelManager:
    """Manages local model backends with auto-detection and fallback."""

    def __init__(self):
        self.backends: List[LocalModelBackend] = []
        self.active_backend: Optional[LocalModelBackend] = None
        self._initialize_backends()

    def _initialize_backends(self) -> None:
        """Initialize priority-ordered backends."""
        # Priority: Ollama first (easiest to use), then llama.cpp
        self.backends = [
            OllamaBackend(),
            LlamaCppBackend(),
        ]

    def detect_and_initialize(self) -> bool:
        """Auto-detect and initialize available backend."""
        logger.info("Auto-detecting local AI backends...")

        for backend in self.backends:
            try:
                if backend.initialize():
                    self.active_backend = backend
                    info = backend.get_model_info()
                    if info:
                        logger.info(f"✓ Initialized {info.backend}: {info.name} ({info.size_gb:.1f}GB)")
                    return True
            except Exception as e:
                logger.debug(f"Backend {backend.__class__.__name__} failed: {e}")

        logger.warning("No local AI backend available")
        return False

    def is_ready(self) -> bool:
        """Check if local model is ready."""
        return self.active_backend is not None and self.active_backend.initialized

    def infer(self, request: LocalInferenceRequest) -> LocalInferenceResponse:
        """Run inference using active backend."""
        if not self.active_backend:
            return LocalInferenceResponse(
                text="",
                tokens_used=0,
                stop_reason="error",
                error="No AI backend available"
            )

        return self.active_backend.infer(request)

    def get_model_info(self) -> Optional[LocalModelInfo]:
        """Get information about active model."""
        if not self.active_backend:
            return None
        return self.active_backend.get_model_info()

    def shutdown(self) -> None:
        """Shutdown all backends."""
        if self.active_backend:
            self.active_backend.shutdown()
        self.active_backend = None

    def get_status(self) -> Dict[str, Any]:
        """Get detailed status of AI system."""
        return {
            "available": self.is_ready(),
            "backend": self.active_backend.__class__.__name__ if self.active_backend else None,
            "model": self.get_model_info(),
            "backends_available": len([b for b in self.backends if b.is_available()])
        }

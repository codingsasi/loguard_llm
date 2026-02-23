"""
Ollama client for LLM inference and embeddings.
Communicates with Ollama API via HTTP.
"""
import httpx
import logging
from typing import List, Optional, Dict, Any
from django.conf import settings

logger = logging.getLogger(__name__)


class OllamaClient:
    """
    Client for interacting with Ollama API.
    Handles both LLM generation and embeddings.
    """
    
    def __init__(self, base_url: Optional[str] = None):
        self.base_url = base_url or settings.OLLAMA_BASE_URL
        self.client = httpx.Client(timeout=600.0)  # 10 minute timeout for large models
    
    def generate(
        self,
        model: str,
        prompt: str,
        system: Optional[str] = None,
        temperature: float = 0.1,
        max_tokens: Optional[int] = None,
    ) -> Dict[str, Any]:
        """
        Generate text using an Ollama model.
        
        Args:
            model: Model name (e.g., 'mistral:7b-instruct')
            prompt: User prompt
            system: Optional system prompt
            temperature: Sampling temperature (0.0-1.0)
            max_tokens: Maximum tokens to generate
        
        Returns:
            Dict with 'response', 'model', 'total_duration', etc.
        """
        payload = {
            "model": model,
            "prompt": prompt,
            "stream": False,
            "options": {
                "temperature": temperature,
            }
        }
        
        if system:
            payload["system"] = system
        
        if max_tokens:
            payload["options"]["num_predict"] = max_tokens
        
        try:
            response = self.client.post(
                f"{self.base_url}/api/generate",
                json=payload
            )
            response.raise_for_status()
            return response.json()
        except httpx.HTTPError as e:
            logger.error(f"Ollama generate error: {e}")
            raise
    
    def embed(self, model: str, text: str) -> List[float]:
        """
        Generate embeddings for text.
        
        Args:
            model: Embedding model name (e.g., 'nomic-embed-text')
            text: Text to embed
        
        Returns:
            List of floats representing the embedding vector
        """
        payload = {
            "model": model,
            "prompt": text,
        }
        
        try:
            response = self.client.post(
                f"{self.base_url}/api/embeddings",
                json=payload
            )
            response.raise_for_status()
            result = response.json()
            return result.get("embedding", [])
        except httpx.HTTPError as e:
            logger.error(f"Ollama embed error: {e}")
            raise
    
    def embed_batch(self, model: str, texts: List[str]) -> List[List[float]]:
        """
        Generate embeddings for multiple texts.
        
        Args:
            model: Embedding model name
            texts: List of texts to embed
        
        Returns:
            List of embedding vectors
        """
        embeddings = []
        for text in texts:
            embedding = self.embed(model, text)
            embeddings.append(embedding)
        return embeddings
    
    def list_models(self) -> List[Dict[str, Any]]:
        """
        List available models in Ollama.
        
        Returns:
            List of model info dicts
        """
        try:
            response = self.client.get(f"{self.base_url}/api/tags")
            response.raise_for_status()
            result = response.json()
            return result.get("models", [])
        except httpx.HTTPError as e:
            logger.error(f"Ollama list models error: {e}")
            return []
    
    def pull_model(self, model: str) -> bool:
        """
        Pull a model from Ollama library.
        
        Args:
            model: Model name to pull

        Returns:
            True if successful
        """
        payload = {"name": model}
        
        try:
            response = self.client.post(
                f"{self.base_url}/api/pull",
                json=payload
            )
            response.raise_for_status()
            logger.info(f"Successfully pulled model: {model}")
            return True
        except httpx.HTTPError as e:
            logger.error(f"Ollama pull model error: {e}")
            return False

    def check_health(self) -> bool:
        """
        Check if Ollama service is healthy.
        
        Returns:
            True if service is responding
        """
        try:
            response = self.client.get(f"{self.base_url}/api/tags")
            return response.status_code == 200
        except Exception:
            return False
    
    def __del__(self):
        """Close HTTP client on cleanup."""
        try:
            self.client.close()
        except Exception:
            pass

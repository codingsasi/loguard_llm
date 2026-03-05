"""
Embedding generation for log chunks.
Uses Ollama embedding models with two-tier strategy:
- FastLogEmbedder: Quick embeddings for individual logs (mxbai)
- ContextEmbedder: Large context for groups and summaries (bge-m3)
"""
import logging
from typing import List
from engine.llm.ollama_client import OllamaClient

logger = logging.getLogger(__name__)


class FastLogEmbedder:
    """
    Fast embedder for individual log lines using mxbai-embed-large.
    Optimized for speed - processes single logs quickly.
    """
    
    def __init__(self, model: str = "mxbai-embed-large"):
        self.model = model
        self.client = OllamaClient()
        self._ensure_model_available()
    
    def _ensure_model_available(self):
        """Check if embedding model is available, pull if needed."""
        models = self.client.list_models()
        model_names = [m.get("name", "") for m in models]
        
        if not any(self.model in name for name in model_names):
            logger.info(f"Fast embedding model {self.model} not found, pulling...")
            self.client.pull_model(self.model)
    
    def embed(self, text: str) -> List[float]:
        """
        Generate embedding for a single sentencified log.
        
        Args:
            text: Sentencified log text (key-value format)
        
        Returns:
            Embedding vector as list of floats
        """
        try:
            embedding = self.client.embed(self.model, text)
            return embedding
        except Exception as e:
            logger.error(f"Error generating fast embedding: {e}")
            raise


class ContextEmbedder:
    """
    Large context embedder for grouped summaries and analysis summaries using bge-m3.
    Supports up to 8K token context for richer semantic understanding.
    """
    
    def __init__(self, model: str = "bge-m3"):
        self.model = model
        self.client = OllamaClient()
        self._ensure_model_available()
    
    def _ensure_model_available(self):
        """Check if embedding model is available, pull if needed."""
        models = self.client.list_models()
        model_names = [m.get("name", "") for m in models]
        
        if not any(self.model in name for name in model_names):
            logger.info(f"Context embedding model {self.model} not found, pulling...")
            self.client.pull_model(self.model)
    
    def embed(self, text: str) -> List[float]:
        """
        Generate embedding for a group summary or analysis summary.
        
        Args:
            text: Summary text (key-value format)
        
        Returns:
            Embedding vector as list of floats
        """
        try:
            embedding = self.client.embed(self.model, text)
            return embedding
        except Exception as e:
            logger.error(f"Error generating context embedding: {e}")
            raise
    
    def embed_batch(self, texts: List[str]) -> List[List[float]]:
        """
        Generate embeddings for multiple summaries.
        
        Args:
            texts: List of summary texts to embed
        
        Returns:
            List of embedding vectors
        """
        try:
            embeddings = self.client.embed_batch(self.model, texts)
            return embeddings
        except Exception as e:
            logger.error(f"Error generating batch context embeddings: {e}")
            raise


# Legacy class - kept for backward compatibility with existing batch mode
class LogEmbedder:
    """
    Generates embeddings for log chunks using Ollama.
    """
    
    def __init__(self, model: str = "nomic-embed-text"):
        self.model = model
        self.client = OllamaClient()
        self._ensure_model_available()
    
    def _ensure_model_available(self):
        """Check if embedding model is available, pull if needed."""
        models = self.client.list_models()
        model_names = [m.get("name", "") for m in models]
        
        if not any(self.model in name for name in model_names):
            logger.info(f"Embedding model {self.model} not found, pulling...")
            self.client.pull_model(self.model)
    
    def embed(self, text: str) -> List[float]:
        """
        Generate embedding for a single text.
        
        Args:
            text: Text to embed
        
        Returns:
            Embedding vector as list of floats
        """
        try:
            embedding = self.client.embed(self.model, text)
            return embedding
        except Exception as e:
            logger.error(f"Error generating embedding: {e}")
            raise
    
    def embed_batch(self, texts: List[str]) -> List[List[float]]:
        """
        Generate embeddings for multiple texts.
        
        Args:
            texts: List of texts to embed
        
        Returns:
            List of embedding vectors
        """
        try:
            embeddings = self.client.embed_batch(self.model, texts)
            return embeddings
        except Exception as e:
            logger.error(f"Error generating batch embeddings: {e}")
            raise
    
    def embed_chunks(self, chunks: List) -> List[tuple]:
        """
        Generate embeddings for log chunks.
        
        Args:
            chunks: List of LogChunk objects
        
        Returns:
            List of (chunk, embedding) tuples
        """
        texts = [chunk.to_text() for chunk in chunks]
        embeddings = self.embed_batch(texts)
        return list(zip(chunks, embeddings))

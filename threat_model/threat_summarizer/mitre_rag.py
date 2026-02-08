"""
MITRE ATT&CK RAG (Retrieval-Augmented Generation) Module.

Provides semantic search over MITRE ATT&CK techniques to ground LLM responses
in authoritative threat intelligence framework data.
"""
import json
import os
import logging
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple
from datetime import datetime

import requests

# Lazy imports for heavy dependencies
_chromadb = None
_SentenceTransformer = None

logger = logging.getLogger(__name__)

# Constants
MITRE_ATTACK_URL = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
CACHE_DIR = Path.home() / ".cache" / "mitre_attack"
ATTACK_DATA_FILE = CACHE_DIR / "enterprise-attack.json"
CHROMA_PERSIST_DIR = CACHE_DIR / "chroma_db"

# Embedding model - all-MiniLM is fast and good for semantic similarity
EMBEDDING_MODEL = "all-MiniLM-L6-v2"


def _get_chromadb():
    """Lazy load chromadb."""
    global _chromadb
    if _chromadb is None:
        import chromadb
        _chromadb = chromadb
    return _chromadb


def _get_sentence_transformer():
    """Lazy load sentence transformer."""
    global _SentenceTransformer
    if _SentenceTransformer is None:
        from sentence_transformers import SentenceTransformer
        _SentenceTransformer = SentenceTransformer
    return _SentenceTransformer


class MitreRAG:
    """
    RAG system for MITRE ATT&CK framework.
    
    Provides semantic search over techniques to retrieve relevant context
    for threat analysis and TTP mapping.
    """
    
    def __init__(self, persist_dir: Optional[Path] = None):
        """
        Initialize the MITRE RAG system.
        
        Args:
            persist_dir: Directory to persist ChromaDB. Defaults to ~/.cache/mitre_attack/chroma_db
        """
        self.persist_dir = persist_dir or CHROMA_PERSIST_DIR
        self.persist_dir.parent.mkdir(parents=True, exist_ok=True)
        
        self._client = None
        self._collection = None
        self._embedder = None
        self._techniques: Dict[str, Dict[str, Any]] = {}
        self._initialized = False
    
    @property
    def client(self):
        """Lazy load ChromaDB client."""
        if self._client is None:
            chromadb = _get_chromadb()
            self._client = chromadb.PersistentClient(path=str(self.persist_dir))
        return self._client
    
    @property
    def embedder(self):
        """Lazy load sentence transformer model."""
        if self._embedder is None:
            SentenceTransformer = _get_sentence_transformer()
            self._embedder = SentenceTransformer(EMBEDDING_MODEL)
        return self._embedder
    
    def download_mitre_attack(self, force: bool = False) -> Path:
        """
        Download MITRE ATT&CK STIX data.
        
        Args:
            force: Force re-download even if cached.
            
        Returns:
            Path to the downloaded file.
        """
        CACHE_DIR.mkdir(parents=True, exist_ok=True)
        
        # Check if we need to download
        if ATTACK_DATA_FILE.exists() and not force:
            # Check if file is less than 7 days old
            age_days = (datetime.now().timestamp() - ATTACK_DATA_FILE.stat().st_mtime) / 86400
            if age_days < 7:
                logger.info(f"Using cached MITRE ATT&CK data (age: {age_days:.1f} days)")
                return ATTACK_DATA_FILE
        
        logger.info("Downloading MITRE ATT&CK Enterprise data...")
        try:
            response = requests.get(MITRE_ATTACK_URL, timeout=60)
            response.raise_for_status()
            
            with open(ATTACK_DATA_FILE, "w") as f:
                f.write(response.text)
            
            logger.info(f"Downloaded MITRE ATT&CK data to {ATTACK_DATA_FILE}")
            return ATTACK_DATA_FILE
            
        except Exception as e:
            logger.error(f"Failed to download MITRE ATT&CK data: {e}")
            if ATTACK_DATA_FILE.exists():
                logger.info("Using existing cached data")
                return ATTACK_DATA_FILE
            raise
    
    def _parse_stix_data(self, data_file: Path) -> List[Dict[str, Any]]:
        """
        Parse STIX data and extract techniques.
        
        Returns:
            List of technique dictionaries with id, name, description, tactics, etc.
        """
        with open(data_file) as f:
            stix_data = json.load(f)
        
        techniques = []
        tactics_map = {}
        
        # First pass: collect tactics
        for obj in stix_data.get("objects", []):
            if obj.get("type") == "x-mitre-tactic":
                short_name = obj.get("x_mitre_shortname", "")
                tactics_map[short_name] = obj.get("name", "")
        
        # Second pass: collect techniques
        for obj in stix_data.get("objects", []):
            if obj.get("type") != "attack-pattern":
                continue
            if obj.get("revoked", False) or obj.get("x_mitre_deprecated", False):
                continue
            
            # Extract technique ID from external references
            technique_id = ""
            for ref in obj.get("external_references", []):
                if ref.get("source_name") == "mitre-attack":
                    technique_id = ref.get("external_id", "")
                    break
            
            if not technique_id:
                continue
            
            # Extract tactics (kill chain phases)
            tactics = []
            for phase in obj.get("kill_chain_phases", []):
                phase_name = phase.get("phase_name", "")
                tactic_name = tactics_map.get(phase_name, phase_name.replace("-", " ").title())
                tactics.append(tactic_name)
            
            # Build technique record
            technique = {
                "id": technique_id,
                "name": obj.get("name", ""),
                "description": obj.get("description", ""),
                "tactics": tactics,
                "platforms": obj.get("x_mitre_platforms", []),
                "detection": obj.get("x_mitre_detection", ""),
                "is_subtechnique": "." in technique_id,
            }
            techniques.append(technique)
            self._techniques[technique_id] = technique
        
        logger.info(f"Parsed {len(techniques)} MITRE ATT&CK techniques")
        return techniques
    
    def _build_embeddings(self, techniques: List[Dict[str, Any]]) -> None:
        """Build and store embeddings in ChromaDB."""
        # Get or create collection
        try:
            self._collection = self.client.get_collection("mitre_attack")
            existing_count = self._collection.count()
            if existing_count >= len(techniques) - 10:  # Allow small variance
                logger.info(f"Using existing ChromaDB collection ({existing_count} techniques)")
                return
            # Delete old collection if it exists but is incomplete
            self.client.delete_collection("mitre_attack")
        except Exception:
            pass
        
        self._collection = self.client.create_collection(
            name="mitre_attack",
            metadata={"description": "MITRE ATT&CK Enterprise techniques"}
        )
        
        logger.info(f"Building embeddings for {len(techniques)} techniques...")
        
        # Prepare documents for embedding
        ids = []
        documents = []
        metadatas = []
        
        for tech in techniques:
            # Create searchable text combining key fields
            doc_text = f"{tech['id']} {tech['name']}: {tech['description'][:500]}"
            if tech['tactics']:
                doc_text += f" Tactics: {', '.join(tech['tactics'])}"
            
            ids.append(tech['id'])
            documents.append(doc_text)
            metadatas.append({
                "name": tech['name'],
                "tactics": ", ".join(tech['tactics']),
                "is_subtechnique": tech['is_subtechnique'],
            })
        
        # Generate embeddings
        embeddings = self.embedder.encode(documents, show_progress_bar=True).tolist()
        
        # Add to ChromaDB in batches
        batch_size = 100
        for i in range(0, len(ids), batch_size):
            end_idx = min(i + batch_size, len(ids))
            self._collection.add(
                ids=ids[i:end_idx],
                documents=documents[i:end_idx],
                embeddings=embeddings[i:end_idx],
                metadatas=metadatas[i:end_idx],
            )
        
        logger.info(f"Built ChromaDB collection with {len(ids)} techniques")
    
    def initialize(self, force_download: bool = False) -> None:
        """
        Initialize the RAG system by downloading data and building embeddings.
        
        Args:
            force_download: Force re-download of MITRE data.
        """
        if self._initialized and not force_download:
            return
        
        # Download MITRE ATT&CK data
        data_file = self.download_mitre_attack(force=force_download)
        
        # Parse techniques
        techniques = self._parse_stix_data(data_file)
        
        # Build/load embeddings
        self._build_embeddings(techniques)
        
        self._initialized = True
        logger.info("MITRE RAG system initialized")
    
    def retrieve_context(
        self, 
        query: str, 
        top_k: int = 3,
        include_subtechniques: bool = True
    ) -> List[Dict[str, Any]]:
        """
        Retrieve relevant MITRE ATT&CK techniques for a query.
        
        Args:
            query: The threat description or IOC to search for.
            top_k: Number of results to return.
            include_subtechniques: Whether to include sub-techniques.
            
        Returns:
            List of matching techniques with similarity scores.
        """
        if not self._initialized:
            self.initialize()
        
        if self._collection is None:
            logger.warning("ChromaDB collection not initialized")
            return []
        
        # Generate query embedding
        query_embedding = self.embedder.encode([query]).tolist()
        
        # Search ChromaDB
        results = self._collection.query(
            query_embeddings=query_embedding,
            n_results=top_k * 2 if not include_subtechniques else top_k,
            include=["documents", "metadatas", "distances"]
        )
        
        # Process results
        retrieved = []
        for i, (doc_id, distance, metadata) in enumerate(zip(
            results["ids"][0],
            results["distances"][0],
            results["metadatas"][0]
        )):
            # Filter sub-techniques if requested
            if not include_subtechniques and metadata.get("is_subtechnique"):
                continue
            
            # Convert distance to similarity score (ChromaDB uses L2 distance)
            similarity = 1 / (1 + distance)
            
            technique_data = self._techniques.get(doc_id, {})
            retrieved.append({
                "technique_id": doc_id,
                "technique_name": metadata.get("name", ""),
                "tactics": metadata.get("tactics", "").split(", "),
                "description": technique_data.get("description", "")[:300],
                "similarity": round(similarity, 3),
            })
            
            if len(retrieved) >= top_k:
                break
        
        return retrieved
    
    def get_technique(self, technique_id: str) -> Optional[Dict[str, Any]]:
        """Get full technique details by ID."""
        if not self._initialized:
            self.initialize()
        return self._techniques.get(technique_id)
    
    def get_stats(self) -> Dict[str, Any]:
        """Get statistics about the knowledge base."""
        return {
            "total_techniques": len(self._techniques),
            "initialized": self._initialized,
            "persist_dir": str(self.persist_dir),
            "embedding_model": EMBEDDING_MODEL,
        }
    
    def format_context_for_prompt(self, techniques: List[Dict[str, Any]]) -> str:
        """
        Format retrieved techniques as context for LLM prompt.
        
        Args:
            techniques: List of retrieved technique dictionaries.
            
        Returns:
            Formatted string for prompt injection.
        """
        if not techniques:
            return ""
        
        lines = ["[MITRE ATT&CK CONTEXT]"]
        for tech in techniques:
            tactics = ", ".join(tech.get("tactics", [])) if tech.get("tactics") else "Unknown"
            lines.append(
                f"- {tech['technique_id']} ({tech['technique_name']}): "
                f"Tactics: {tactics}. {tech.get('description', '')[:150]}..."
            )
        
        return "\n".join(lines)


# Singleton instance for reuse
_rag_instance: Optional[MitreRAG] = None


def get_mitre_rag() -> MitreRAG:
    """Get or create the singleton MitreRAG instance."""
    global _rag_instance
    if _rag_instance is None:
        _rag_instance = MitreRAG()
    return _rag_instance

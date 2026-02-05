
"""
Phishing Detector - AI-Powered Threat Intelligence System
Copyright (c) 2026 BaoZ
"""

import os
import logging
from typing import List, Dict, Any, Optional
import chromadb
from chromadb.config import Settings
from sentence_transformers import SentenceTransformer

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class KnowledgeBaseService:
    """
    Manages semantic search using ChromaDB and SentenceTransformers.
    Optimized for FastAPI integration on VPS/Linux environments.
    """
    
    _instance = None
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(KnowledgeBaseService, cls).__new__(cls)
            cls._instance.initialized = False
        return cls._instance
    
    def __init__(self):
        if self.initialized:
            return
            
        try:
            # Persistent path relative to root
            self.persist_path = './chroma_db'
            
            # Initialize ChromaDB client (Persistent)
            logger.info(f"Initializing ChromaDB client at {self.persist_path}...")
            self.client = chromadb.PersistentClient(path=self.persist_path)
            
            # Initialize Embedding Model
            logger.info("Loading embedding model all-MiniLM-L6-v2...")
            self.embedding_model = SentenceTransformer('all-MiniLM-L6-v2')
            
            # Get or Create Collection
            self.collection = self.client.get_or_create_collection(
                name="phishing_threats",
                metadata={"hnsw:space": "cosine"}  # Use cosine distance
            )
            
            self.initialized = True
            logger.info("KnowledgeBaseService initialized successfully.")
            
        except Exception as e:
            logger.error(f"Failed to initialize KnowledgeBaseService: {e}")
            # Ensure we don't crash the app, but service will be degraded
            self.initialized = False
            self.client = None
            self.collection = None

    def ingest_phishtank_data(self, limit: int = 1000) -> bool:
        """
        Ingest data logic. 
        Note: This was part of the previous requirement. 
        Re-implementing to ensure compatibility with ingestion scripts.
        """
        if not self.initialized or not self.collection:
            logger.error("KnowledgeBaseService not initialized correctly.")
            return False
            
        try:
            import requests
            url_feed = "http://data.phishtank.com/data/online-valid.json"
            logger.info(f"Downloading PhishTank data from {url_feed}...")
            
            response = requests.get(url_feed, timeout=30)
            response.raise_for_status()
            data = response.json()
            
            logger.info(f"Downloaded {len(data)} entries. Processing top {limit}...")
            
            documents = []
            metadatas = []
            ids = []
            subset = data[:limit]
            
            for entry in subset:
                phish_id = str(entry.get('phish_id'))
                target_url = entry.get('url')
                target = entry.get('target', 'Unknown')
                
                text = f"URL: {target_url} | Target: {target} | PhishID: {phish_id}"
                
                documents.append(text)
                metadatas.append({
                    "phish_id": phish_id,
                    "url": target_url,
                    "target": target,
                    "verified": entry.get('verified', 'no'),
                    "submission_time": entry.get('submission_time', '')
                })
                ids.append(phish_id)
            
            if documents:
                # Embed (SentenceTransformer)
                logger.info("Generating embeddings...")
                embeddings = self.embedding_model.encode(documents).tolist()
                
                logger.info("Upserting to ChromaDB...")
                self.collection.upsert(
                    ids=ids,
                    embeddings=embeddings,
                    documents=documents,
                    metadatas=metadatas
                )
                logger.info(f"Successfully ingested {len(documents)} items.")
                return True
            
            return False
            
        except Exception as e:
            logger.error(f"Error ingesting data: {e}")
            return False

    def search_similar_threats(self, url: str, limit: int = 3) -> List[Dict[str, Any]]:
        """
        Search for similar threats in the vector database.
        
        Args:
            url (str): The URL text to search for.
            limit (int): Number of results to return.
            
        Returns:
            List[Dict]: List of similar threats with metadata and score.
        """
        if not self.initialized or not self.collection:
            logger.warning("KnowledgeBaseService not initialized. Returning empty results.")
            return []
            
        try:
            # Embed the input URL
            query_embedding = self.embedding_model.encode([url]).tolist()
            
            # Query the collection
            results = self.collection.query(
                query_embeddings=query_embedding,
                n_results=limit
            )
            
            similar_threats = []
            
            if results['ids'] and len(results['ids'][0]) > 0:
                for i in range(len(results['ids'][0])):
                    distance = results['distances'][0][i]
                    
                    # Filter results: Only return items with distance < 0.5
                    # Cosine distance: 0 is identical, 1 is orthogonal, 2 is opposite.
                    # < 0.5 implies high similarity.
                    if distance < 0.5:
                        similarity_score = 1 - distance
                        metadata = results['metadatas'][0][i]
                        
                        threat_info = {
                            "similar_url": metadata.get('url'),
                            "target": metadata.get('target'),
                            "phish_id": metadata.get('phish_id'),
                            "distance": distance,
                            "similarity_score": similarity_score,
                            "raw_metadata": metadata # Keep full metadata accessible
                        }
                        similar_threats.append(threat_info)
            
            return similar_threats
            
        except Exception as e:
            logger.error(f"Error searching similar threats: {e}")
            return []

# Create singleton instance exposed as 'knowledge_base' to match existing imports
knowledge_base = KnowledgeBaseService()

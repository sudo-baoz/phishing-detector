
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
            self.cache_path = './data/phishtank_cache.json'
            self.phishing_cache = set()
            
            # Ensure data dir exists
            import os
            os.makedirs('./data', exist_ok=True)
            
            # Load cache if exists
            self.load_local_cache()
            
            # Initialize ChromaDB client (Persistent) with telemetry disabled
            logger.info(f"Initializing ChromaDB client at {self.persist_path}...")
            self.client = chromadb.PersistentClient(
                path=self.persist_path,
                settings=Settings(anonymized_telemetry=False)
            )
            
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
            self.phishing_cache = set()

    def load_local_cache(self):
        """Load local JSON cache into memory set for O(1) lookup"""
        import json
        try:
            if os.path.exists(self.cache_path):
                logger.info(f"Loading PhishTank local cache from {self.cache_path}...")
                with open(self.cache_path, 'r') as f:
                    data = json.load(f)
                    self.phishing_cache = set(data.get('urls', []))
                logger.info(f"Loaded {len(self.phishing_cache)} URLs into memory cache.")
            else:
                logger.info("No local PhishTank cache found. Waiting for ingestion.")
        except Exception as e:
            logger.error(f"Failed to load local cache: {e}")

    def check_known_phish(self, url: str) -> Dict[str, Any]:
        """
        O(1) Exact match check against local PhishTank cache.
        Returns immediate verdict if found.
        """
        if url in self.phishing_cache:
            logger.warning(f"[FAIL-FAST] PhishTank Exact Match: {url}")
            return {
                'match': True,
                'source': 'PhishTank (Local Cache)',
                'risk': True
            }
        
        # Check stripping protocol
        domain_uri = url.split('://')[-1] if '://' in url else url
        if domain_uri in self.phishing_cache:
             return {
                'match': True,
                'source': 'PhishTank (Local Cache)',
                'risk': True
            }
            
        return {'match': False, 'risk': False}

    def ingest_phishtank_data(self, limit: int = 1000) -> bool:
        """
        Ingest data logic. 
        Downloads PhishTank DB, updates local cache (O(1)), and Vector DB (RAG).
        """
        if not self.initialized or not self.collection:
            logger.error("KnowledgeBaseService not initialized correctly.")
            return False
            
        try:
            import requests
            import json
            url_feed = "http://data.phishtank.com/data/online-valid.json"
            logger.info(f"Downloading PhishTank data from {url_feed}...")
            
            response = requests.get(url_feed, timeout=60) # Increased timeout
            response.raise_for_status()
            data = response.json()
            
            logger.info(f"Downloaded {len(data)} entries.")
            
            # 1. Update In-Memory Cache & Local File (Optimization)
            all_urls = [entry.get('url') for entry in data]
            self.phishing_cache = set(all_urls)
            
            # Save to disk
            with open(self.cache_path, 'w') as f:
                json.dump({'urls': list(self.phishing_cache), 'updated': str(datetime.now())}, f)
            logger.info(f"Updated local cache with {len(self.phishing_cache)} URLs.")
            
            # 2. Process for Vector DB (Limit for performance)
            logger.info(f"Processing top {limit} for Vector RAG...")
            
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

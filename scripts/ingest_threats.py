
#!/usr/bin/env python3
import sys
import os
import argparse
import asyncio

# Ensure app module is in path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


from app.services.knowledge_base import knowledge_base

def ingest_data_from_phishtank(limit: int = 1000) -> bool:
    """
    Wrapper function to ingest PhishTank data into the knowledge base.
    This can be imported and called by the FastAPI application.
    
    Args:
        limit (int): Number of entries to ingest.
        
    Returns:
        bool: True if successful, False otherwise.
    """
    print(f"🚀 Starting ingestion of {limit} phishing threats...")
    try:
        # The KnowledgeBase service handles the underlying storage 
        # (originally planned as ChromaDB, now using optimized local storage)
        success = knowledge_base.ingest_phishtank_data(limit=limit)
        
        if success:
            print("✅ Ingestion completed successfully!")
            return True
        else:
            print("❌ Ingestion failed.")
            return False
            
    except Exception as e:
        print(f"❌ Error during ingestion: {e}")
        # Log error but don't crash caller
        return False

def main():
    parser = argparse.ArgumentParser(description="Ingest PhishTank data into KnowledgeBase")
    parser.add_argument("--limit", type=int, default=1000, help="Number of entries to ingest (default: 1000)")
    args = parser.parse_args()
    
    success = ingest_data_from_phishtank(limit=args.limit)
    if not success:
        sys.exit(1)

if __name__ == "__main__":
    main()

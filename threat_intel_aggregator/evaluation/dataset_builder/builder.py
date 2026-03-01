"""
Dataset Builder Orchestrator.

Manages the pipeline of fetching raw reports, sending them to the 
TeacherLabeler, and compiling the final GroundTruthDataset JSON.
"""

import json
import logging
from typing import List, Dict, Any, Optional
from pathlib import Path
from threat_intel_aggregator.evaluation.dataset_builder.labeler import TeacherLabeler
from threat_intel_aggregator.evaluation.ground_truth import GroundTruthSample

logger = logging.getLogger(__name__)

class DatasetBuilder:
    """Orchestrates the creation of a 500+ sample ground-truth dataset."""
    
    def __init__(self, model: str = "qwen2.5:7b", api_url: Optional[str] = None):
        self.labeler = TeacherLabeler(model=model, api_url=api_url)
        self.samples: List[GroundTruthSample] = []
        
    def add_raw_samples(self, raw_data: List[Dict[str, str]], base_id: str = "real_world"):
        """
        Process a list of raw report dicts.
        Each dict should have 'text' and optionally 'id', 'category', 'tags'.
        """
        for i, item in enumerate(raw_data):
            text = item.get("text")
            if not text:
                continue
                
            sample_id = item.get("id", f"{base_id}_{len(self.samples) + 1:04d}")
            category = item.get("category", "true_positive")
            tags = item.get("tags", [])
            
            sample = self.labeler.label_text(
                text=text,
                sample_id=sample_id,
                category=category,
                tags=tags
            )
            self.samples.append(sample)
            
            if (i + 1) % 10 == 0:
                logger.info(f"Processed {i + 1}/{len(raw_data)} samples.")

    def save_dataset(self, output_path: str):
        """Save the compiled samples as a GroundTruthDataset JSON."""
        data = {
            "samples": [s.to_dict() for s in self.samples]
        }
        
        output_file = Path(output_path)
        output_file.parent.mkdir(parents=True, exist_ok=True)
        
        with open(output_file, "w") as f:
            json.dump(data, f, indent=2)
            
        logger.info(f"Successfully saved {len(self.samples)} samples to {output_path}")

def build_from_file(input_path: str, output_path: str, model: str = "qwen2.5:7b"):
    """Convenience function to build a dataset from a raw text/JSON file."""
    builder = DatasetBuilder(model=model)
    
    with open(input_path, "r") as f:
        # Assume it's a list of dicts with 'text'
        raw_data = json.load(f)
        
    if isinstance(raw_data, dict) and "samples" in raw_data:
        raw_data = raw_data["samples"]
        
    builder.add_raw_samples(raw_data)
    builder.save_dataset(output_path)

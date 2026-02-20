"""
Reporter Model for Section 2

Takes normalized JSON packets from Section 1 and generates:
1. Technical summary sentences via Gemini LLM
2. Enriched packets ready for MITRE ATT&CK mapping
"""

import json
import hashlib
import time
from pathlib import Path
from typing import Optional
import google.genai

from .config import ReporterConfig
from .prompts import SummaryPrompts


class Reporter:
    """
    Reporter Model for generating technical summaries from security findings.
    
    Workflow:
    1. Load JSON packet (from Section 1 output)
    2. For each finding, generate a technical summary sentence
    3. Store summary in finding metadata
    4. Output enriched packet ready for Section 3 (ATT&CK mapping)
    """
    
    def __init__(self):
        """Initialize Reporter with Gemini API."""
        ReporterConfig.ensure_cache_dir()
        
        if not ReporterConfig.validate():
            raise ValueError("Reporter configuration validation failed")
        
        # Initialize Gemini API with new google.genai package
        self.client = google.genai.Client(api_key=ReporterConfig.GEMINI_API_KEY)
        
        self.report_count = 0
        self.cache_hits = 0
        self.cache_misses = 0
    
    def _get_cache_key(self, finding_dict: dict) -> str:
        """Generate cache key for a finding."""
        # Create deterministic hash from key finding properties
        cache_input = f"{finding_dict.get('title', '')}{finding_dict.get('description', '')[:100]}"
        return hashlib.md5(cache_input.encode()).hexdigest()
    
    def _load_from_cache(self, cache_key: str) -> Optional[str]:
        """Load summary from cache if available."""
        if not ReporterConfig.ENABLE_CACHE:
            return None
        
        cache_file = ReporterConfig.CACHE_DIR / f"{cache_key}.txt"
        if cache_file.exists():
            self.cache_hits += 1
            return cache_file.read_text().strip()
        
        self.cache_misses += 1
        return None
    
    def _save_to_cache(self, cache_key: str, summary: str):
        """Save summary to cache."""
        if not ReporterConfig.ENABLE_CACHE:
            return
        
        cache_file = ReporterConfig.CACHE_DIR / f"{cache_key}.txt"
        cache_file.write_text(summary)
    
    def generate_summary(self, finding_dict: dict) -> tuple[str, bool]:
        """
        Generate a technical summary sentence for a single finding.
        
        Args:
            finding_dict: Dictionary with finding data
        
        Returns:
            Tuple of (technical summary sentence, cache_hit flag).\r\n            On errors, returns (error message, False).
        """
        # Check cache first
        cache_key = self._get_cache_key(finding_dict)
        cached_summary = self._load_from_cache(cache_key)
        if cached_summary:
            return cached_summary, True
        
        # Prepare finding data for prompt
        severity = finding_dict.get('severity', 'UNKNOWN')
        title = finding_dict.get('title', 'Unknown vulnerability')
        description = finding_dict.get('description', '')[:500]  # Limit to first 500 chars
        cves = ', '.join(finding_dict.get('cve_ids', [])) or 'N/A'
        metadata = finding_dict.get('metadata', {})
        services = ', '.join(metadata.get('services', [])) or 'Unknown'
        ports = ', '.join(metadata.get('ports', [])) or 'Unknown'
        cvss_score = finding_dict.get('cvss_score', 'N/A')
        
        # Build user prompt
        user_prompt = SummaryPrompts.USER_PROMPT_TEMPLATE.format(
            severity=severity,
            title=title,
            description=description,
            cves=cves,
            services=services,
            ports=ports,
            cvss_score=cvss_score
        )
        
        try:
            # Call Gemini API with retry logic
            for attempt in range(ReporterConfig.RETRY_ATTEMPTS):
                try:
                    response = self.client.models.generate_content(
                        model=ReporterConfig.GEMINI_MODEL,
                        contents=user_prompt,
                        config={
                            "temperature": ReporterConfig.SUMMARY_TEMPERATURE,
                            "top_p": ReporterConfig.SUMMARY_TOP_P,
                            "max_output_tokens": ReporterConfig.SUMMARY_MAX_TOKENS,
                        }
                    )
                    
                    summary = response.text.strip()
                    
                    # Validate summary is a single sentence
                    if not summary.endswith('.'):
                        summary += '.'
                    
                    # Cache the result
                    self._save_to_cache(cache_key, summary)
                    
                    return summary, False
                
                except Exception as e:
                    if attempt < ReporterConfig.RETRY_ATTEMPTS - 1:
                        print(f"⚠️  Attempt {attempt + 1} failed: {e}. Retrying in {ReporterConfig.RETRY_DELAY_SECONDS}s...")
                        time.sleep(ReporterConfig.RETRY_DELAY_SECONDS)
                    else:
                        raise
        
        except Exception as e:
            error_msg = f"ERROR: Failed to generate summary - {str(e)}"
            print(f"❌ {error_msg}")
            return error_msg, False
    
    def process_packet(self, packet_data: dict, max_findings: Optional[int] = None) -> dict:
        """
        Process a complete JSON packet, generating summaries for all findings.
        
        Args:
            packet_data: IngestedPacket data as dictionary
            max_findings: Optional limit on number of findings to process (for testing)
        
        Returns:
            Enhanced packet with summary in each finding's metadata
        """
        findings = packet_data.get('findings', [])
        
        # Limit findings if specified (for testing)
        if max_findings and len(findings) > max_findings:
            findings = findings[:max_findings]
            print(f"\n📋 Processing first {max_findings} findings (testing mode)...")
        else:
            print(f"\n📋 Processing packet with {len(findings)} findings...")
        
        for i, finding in enumerate(findings, 1):
            # Generate summary
            summary, is_cache_hit = self.generate_summary(finding)
            
            # Add to metadata
            if 'metadata' not in finding:
                finding['metadata'] = {}
            
            finding['metadata']['technical_summary'] = summary
            finding['metadata']['summary_generated_at'] = time.strftime('%Y-%m-%d %H:%M:%S')
            
            # Progress indicator
            if i % 5 == 0 or i == 1:
                print(f"  ✓ {i}/{len(findings)} findings processed")

            # Throttle only when we actually made an API request.
            if not is_cache_hit and i < len(findings):
                time.sleep(1.0)
        
        self.report_count += len(findings)
        
        # Add processing stats to packet metadata
        if 'metadata' not in packet_data:
            packet_data['metadata'] = {}
        
        packet_data['metadata']['reporter_stats'] = {
            'total_findings_summarized': len(findings),
            'cache_hits': self.cache_hits,
            'cache_misses': self.cache_misses,
            'processing_timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
        }
        
        return packet_data
    
    def process_json_file(self, json_file_path: str | Path) -> Optional[dict]:
        """
        Process a JSON file from Section 1 output.
        
        Args:
            json_file_path: Path to JSON file
        
        Returns:
            Enriched packet data
        """
        json_file_path = Path(json_file_path)
        
        if not json_file_path.exists():
            print(f"❌ File not found: {json_file_path}")
            return None
        
        print(f"\n🔄 Loading JSON packet: {json_file_path.name}")
        
        try:
            with open(json_file_path) as f:
                packet_data = json.load(f)
            
            # Process the packet
            enriched_packet = self.process_packet(packet_data)
            
            print(f"✅ Successfully processed {json_file_path.name}")
            return enriched_packet
        
        except Exception as e:
            print(f"❌ Error processing JSON file: {e}")
            return None
    
    def save_enriched_packet(self, packet_data: dict, output_dir: str | Path) -> Optional[Path]:
        """
        Save enriched packet with summaries.
        
        Args:
            packet_data: Enriched packet data
            output_dir: Directory to save to
        
        Returns:
            Path to saved file
        """
        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)
        
        # Generate filename with "enriched" marker
        timestamp = time.strftime('%Y%m%d_%H%M%S')
        source_file = packet_data.get('source_file', 'unknown')
        clean_name = Path(source_file).stem
        output_file = output_dir / f"{clean_name}_enriched_{timestamp}.json"
        
        try:
            with open(output_file, 'w') as f:
                json.dump(packet_data, f, indent=2)
            
            print(f"💾 Saved enriched packet to: {output_file.name}")
            return output_file
        
        except Exception as e:
            print(f"❌ Error saving enriched packet: {e}")
            return None
    
    def get_stats(self) -> dict:
        """Get processing statistics."""
        return {
            'total_findings_processed': self.report_count,
            'cache_hits': self.cache_hits,
            'cache_misses': self.cache_misses,
            'cache_hit_rate': self.cache_hits / (self.cache_hits + self.cache_misses) if (self.cache_hits + self.cache_misses) > 0 else 0,
        }



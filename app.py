import streamlit as st
import pandas as pd
import io
import asyncio
import time
from datetime import datetime
import tempfile
import os
import sys
from pathlib import Path

# Add current directory to path for imports
sys.path.insert(0, str(Path(__file__).parent))

from extractors.html_extractor import HTMLExtractor
from extractors.meta_extractor import MetaExtractor
from extractors.fallback_extractor import FallbackExtractor
from utils.domain_utils import DomainUtils
import aiohttp
import yaml


# Configure Streamlit page
st.set_page_config(
    page_title="Domain Meta Extractor",
    page_icon="🔍",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS for better styling
st.markdown("""
<style>
    .main-header {
        font-size: 2.5rem;
        color: #1f77b4;
        text-align: center;
        margin-bottom: 2rem;
    }
    .upload-container {
        border: 2px dashed #ccc;
        border-radius: 10px;
        padding: 2rem;
        text-align: center;
        margin: 1rem 0;
    }
    .progress-container {
        margin: 1rem 0;
    }
    .stats-box {
        background: #f0f2f6;
        padding: 1rem;
        border-radius: 10px;
        margin: 0.5rem 0;
    }
    .success-message {
        color: #28a745;
        font-weight: bold;
    }
    .error-message {
        color: #dc3545;
        font-weight: bold;
    }
</style>
""", unsafe_allow_html=True)


class StreamlitProgress:
    """Custom progress tracker for Streamlit."""

    def __init__(self, total):
        self.total = total
        self.processed = 0
        self.successful = 0
        self.failed = 0
        self.progress_bar = st.progress(0)
        self.status_text = st.empty()
        self.stats_text = st.empty()

    def update(self, success: bool, domain: str = "", method: str = ""):
        self.processed += 1
        if success:
            self.successful += 1
        else:
            self.failed += 1

        # Update progress bar
        progress = self.processed / self.total
        self.progress_bar.progress(progress)

        # Update status
        if success:
            status = f"✅ Successfully processed: {domain}"
        else:
            status = f"❌ Failed to process: {domain}"

        self.status_text.text(status)

        # Update statistics
        success_rate = (self.successful / self.processed) * 100 if self.processed > 0 else 0
        stats_text = f"""
        **Progress:** {self.processed}/{self.total} ({progress:.1%})

        **Success Rate:** {success_rate:.1f}% ({self.successful} successful, {self.failed} failed)
        """
        self.stats_text.markdown(stats_text)

    def finish(self):
        self.progress_bar.progress(1.0)
        self.status_text.text("🎉 Processing complete!")


class SimpleExtractor:
    """Simplified extractor for Streamlit app."""

    def __init__(self):
        self.config = self.get_default_config()
        self.html_extractor = HTMLExtractor(self.config)
        self.meta_extractor = MetaExtractor(self.config)
        self.fallback_extractor = FallbackExtractor(self.config)

    def get_default_config(self):
        """Get default configuration for Streamlit."""
        return {
            'performance': {
                'timeout': 30,
                'read_timeout': 45,
                'max_retries': 2,
                'concurrency': 10  # Lower concurrency for web app
            },
            'extraction': {
                'enable_js_fallback': False,  # Disable JS for simplicity
                'max_content_length': 1048576,
                'min_title_length': 3,
                'max_title_length': 200,
                'min_description_length': 10,
                'max_description_length': 500
            },
            'advanced': {
                'follow_redirects': True,
                'max_redirects': 5,
                'verify_ssl': True,
                'enable_compression': True
            }
        }

    async def extract_domain(self, domain: str, session, progress_tracker=None) -> dict:
        """Extract meta information from a single domain."""
        start_time = time.time()

        try:
            # Normalize domain
            normalized_domain = DomainUtils.normalize_domain(domain)
            if not normalized_domain:
                return {
                    'domain': domain,
                    'meta_title': '',
                    'meta_description': '',
                    'extraction_method': 'invalid_domain',
                    'status_code': 0,
                    'extraction_time': 0,
                    'error_message': 'Invalid domain format'
                }

            # Create simple headers
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.9',
                'Accept-Encoding': 'gzip, deflate, br'
            }

            # Try extractors in order
            extractors = [
                ('html_extractor', self.html_extractor),
                ('meta_extractor', self.meta_extractor),
                ('fallback_extractor', self.fallback_extractor)
            ]

            for extractor_name, extractor in extractors:
                try:
                    result = await extractor.extract(normalized_domain, session=session, headers=headers)

                    if result.success:
                        extraction_time = time.time() - start_time
                        if progress_tracker:
                            progress_tracker.update(True, normalized_domain, extractor_name)

                        return {
                            'domain': domain,
                            'meta_title': result.title or '',
                            'meta_description': result.description or '',
                            'extraction_method': result.method,
                            'status_code': result.status_code or 200,
                            'extraction_time': round(extraction_time, 2),
                            'error_message': ''
                        }

                except Exception as e:
                    continue

            # All extractors failed
            extraction_time = time.time() - start_time
            if progress_tracker:
                progress_tracker.update(False, normalized_domain, 'none')

            return {
                'domain': domain,
                'meta_title': '',
                'meta_description': '',
                'extraction_method': 'none',
                'status_code': 0,
                'extraction_time': round(extraction_time, 2),
                'error_message': 'All extraction methods failed'
            }

        except Exception as e:
            extraction_time = time.time() - start_time
            if progress_tracker:
                progress_tracker.update(False, domain, 'exception')

            return {
                'domain': domain,
                'meta_title': '',
                'meta_description': '',
                'extraction_method': 'exception',
                'status_code': 0,
                'extraction_time': round(extraction_time, 2),
                'error_message': str(e)
            }

    async def process_domains(self, domains: list, progress_tracker=None):
        """Process a list of domains."""
        connector = aiohttp.TCPConnector(
            limit=20,
            limit_per_host=5,
            ttl_dns_cache=300,
            use_dns_cache=True
        )

        timeout = aiohttp.ClientTimeout(total=30, connect=15)

        async with aiohttp.ClientSession(
            connector=connector,
            timeout=timeout,
            headers={'User-Agent': 'DomainMetaExtractor/1.0'}
        ) as session:

            tasks = []
            for domain in domains:
                task = self.extract_domain(domain, session, progress_tracker)
                tasks.append(task)

            results = await asyncio.gather(*tasks, return_exceptions=True)

            # Process results
            processed_results = []
            for i, result in enumerate(results):
                if isinstance(result, Exception):
                    processed_results.append({
                        'domain': domains[i],
                        'meta_title': '',
                        'meta_description': '',
                        'extraction_method': 'exception',
                        'status_code': 0,
                        'extraction_time': 0,
                        'error_message': str(result)
                    })
                else:
                    processed_results.append(result)

            return processed_results


def main():
    """Main Streamlit application."""

    # Header
    st.markdown('<h1 class="main-header">🔍 Domain Meta Extractor</h1>', unsafe_allow_html=True)
    st.markdown("""
    Extract meta titles and descriptions from domain names with intelligent fallback strategies.
    Upload a CSV file with domains and get enhanced data with meta information.
    """)

    # Sidebar configuration
    st.sidebar.header("⚙️ Configuration")

    # Processing options
    st.sidebar.subheader("Processing Options")
    max_domains = st.sidebar.slider("Maximum domains to process", 10, 1000, 100)
    concurrency = st.sidebar.slider("Concurrency level", 1, 20, 10)
    enable_js = st.sidebar.checkbox("Enable JavaScript rendering", value=False,
                                  help="Enable for better results on dynamic sites (slower)")

    # File upload section
    st.header("📁 Upload CSV File")

    # Create upload container
    upload_container = st.container()
    with upload_container:
        st.markdown('<div class="upload-container">', unsafe_allow_html=True)

        uploaded_file = st.file_uploader(
            "Choose a CSV file with domains",
            type=['csv'],
            help="CSV should have a column named 'domain' with domain names"
        )

        st.markdown('</div>', unsafe_allow_html=True)

    # Sample data section
    with st.expander("📋 View Sample CSV Format"):
        sample_data = pd.DataFrame({
            'domain': ['google.com', 'github.com', 'stackoverflow.com']
        })
        st.write(sample_data)
        st.code("""
domain
google.com
github.com
stackoverflow.com
        """)

    # Processing section
    if uploaded_file is not None:
        try:
            # Read the uploaded file
            df = pd.read_csv(uploaded_file)
            st.success(f"✅ File loaded successfully! Found {len(df)} rows.")

            # Show data preview
            with st.expander("👀 Preview uploaded data"):
                st.dataframe(df.head(10))

            # Check for domain column
            if 'domain' not in df.columns:
                st.error("❌ CSV must contain a 'domain' column!")
                return

            # Extract domains
            domains = df['domain'].dropna().tolist()

            # Limit domains if necessary
            if len(domains) > max_domains:
                st.warning(f"⚠️ Limiting to first {max_domains} domains for demo purposes.")
                domains = domains[:max_domains]

            # Process button
            st.header("🚀 Start Processing")

            col1, col2 = st.columns([1, 1])
            with col1:
                if st.button("🔍 Extract Meta Information", type="primary", use_container_width=True):
                    # Show processing status
                    status_container = st.container()
                    with status_container:
                        st.markdown("### Processing Status")

                        # Initialize progress tracker
                        progress_tracker = StreamlitProgress(len(domains))

                        # Process domains
                        with st.spinner("Processing domains..."):
                            extractor = SimpleExtractor()

                            # Run async processing
                            loop = asyncio.new_event_loop()
                            asyncio.set_event_loop(loop)

                            try:
                                results = loop.run_until_complete(
                                    extractor.process_domains(domains, progress_tracker)
                                )
                            finally:
                                loop.close()

                        # Complete progress
                        progress_tracker.finish()

                    # Create results DataFrame
                    results_df = pd.DataFrame(results)

                    # Show results summary
                    st.header("📊 Results Summary")

                    col1, col2, col3 = st.columns(3)
                    with col1:
                        st.metric("Total Processed", len(results))
                    with col2:
                        successful = len([r for r in results if r['meta_title'] or r['meta_description']])
                        st.metric("Successful", successful)
                    with col3:
                        success_rate = (successful / len(results)) * 100 if results else 0
                        st.metric("Success Rate", f"{success_rate:.1f}%")

                    # Show results table
                    st.header("📋 Results")

                    # Add download button
                    csv = results_df.to_csv(index=False)
                    st.download_button(
                        label="📥 Download Results CSV",
                        data=csv,
                        file_name=f"domain_extraction_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                        mime="text/csv",
                        use_container_width=True
                    )

                    # Display results
                    st.dataframe(results_df, use_container_width=True)

                    # Method breakdown
                    if results:
                        st.header("🔧 Extraction Method Breakdown")
                        method_counts = results_df['extraction_method'].value_counts()
                        st.bar_chart(method_counts)

            with col2:
                st.markdown("---")
                st.markdown("### ℹ️ Information")
                st.info("""
                **What will be extracted:**
                - Meta titles from HTML head
                - Meta descriptions
                - OpenGraph data
                - Fallback content

                **Processing time varies** based on:
                - Number of domains
                - Site responsiveness
                - Network conditions
                """)

        except Exception as e:
            st.error(f"❌ Error processing file: {str(e)}")
            st.error("Please ensure your CSV file has a 'domain' column with valid domain names.")

    # Footer
    st.markdown("---")
    st.markdown("""
    <div style='text-align: center; color: #666; margin-top: 2rem;'>
        Made with ❤️ | Domain Meta Extractor v1.0
    </div>
    """, unsafe_allow_html=True)


if __name__ == "__main__":
    main()
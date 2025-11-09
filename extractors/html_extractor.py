"""
HTML-based meta extractor using lxml for fast parsing.
"""

import asyncio
import aiohttp
from typing import Dict, Optional, Tuple, Any
from lxml import html, etree
import logging
from urllib.parse import urljoin, urlparse

from .base_extractor import BaseExtractor, ExtractionResult

logger = logging.getLogger(__name__)


class HTMLExtractor(BaseExtractor):
    """Fast HTML-based meta extractor using lxml."""

    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.timeout = config.get('performance', {}).get('timeout', 30)
        self.read_timeout = config.get('performance', {}).get('read_timeout', 45)
        self.follow_redirects = config.get('advanced', {}).get('follow_redirects', True)
        self.max_redirects = config.get('advanced', {}).get('max_redirects', 10)
        self.verify_ssl = config.get('advanced', {}).get('verify_ssl', True)
        self.enable_compression = config.get('advanced', {}).get('enable_compression', True)

    async def extract(self, domain: str, **kwargs) -> ExtractionResult:
        """
        Extract meta information from a domain using HTTP requests and HTML parsing.

        Args:
            domain: The domain to extract from
            **kwargs: Additional arguments (may include session, headers, etc.)

        Returns:
            ExtractionResult with the extracted information
        """
        start_time = asyncio.get_event_loop().time()

        # Get session from kwargs or create new one
        session = kwargs.get('session')
        close_session = False

        if not session:
            connector = aiohttp.TCPConnector(
                limit=10,
                limit_per_host=2,
                ttl_dns_cache=300,
                use_dns_cache=True,
                ssl=self.verify_ssl
            )
            timeout = aiohttp.ClientTimeout(total=self.timeout, connect=self.read_timeout)
            session = aiohttp.ClientSession(
                connector=connector,
                timeout=timeout,
                headers=kwargs.get('headers', {}),
                enable_compression=self.enable_compression
            )
            close_session = True

        try:
            # Construct URL
            url = self._construct_url(domain)
            self.logger.debug(f"Extracting from: {url}")

            # Make HTTP request
            async with session.get(
                url,
                allow_redirects=self.follow_redirects,
                max_redirects=self.max_redirects
            ) as response:
                status_code = response.status
                content_type = response.headers.get('content-type', '').lower()

                # Check if response is successful and is HTML
                if not self._is_valid_response(response.status, content_type):
                    return self.create_error_result(
                        domain=domain,
                        error_message=f"Invalid response: {response.status} {content_type}",
                        method="html_extractor",
                        extraction_time=asyncio.get_event_loop().time() - start_time,
                        status_code=response.status
                    )

                # Read content with size limit
                content = await self._read_content_safely(response)
                if not content:
                    return self.create_error_result(
                        domain=domain,
                        error_message="No content received",
                        method="html_extractor",
                        extraction_time=asyncio.get_event_loop().time() - start_time,
                        status_code=response.status
                    )

                # Parse HTML and extract meta information
                title, description = self._extract_from_html(content, url)

                extraction_time = asyncio.get_event_loop().time() - start_time

                if title or description:
                    self.logger.debug(f"Successfully extracted from {domain}")
                    return self.create_success_result(
                        domain=domain,
                        title=title,
                        description=description,
                        method="html_extractor",
                        extraction_time=extraction_time,
                        status_code=status_code
                    )
                else:
                    return self.create_error_result(
                        domain=domain,
                        error_message="No meta information found in HTML",
                        method="html_extractor",
                        extraction_time=extraction_time,
                        status_code=status_code
                    )

        except asyncio.TimeoutError:
            self.logger.warning(f"Timeout for domain {domain}")
            return self.create_error_result(
                domain=domain,
                error_message="Request timeout",
                method="html_extractor",
                extraction_time=asyncio.get_event_loop().time() - start_time
            )

        except aiohttp.ClientError as e:
            self.logger.warning(f"Client error for {domain}: {str(e)}")
            return self.create_error_result(
                domain=domain,
                error_message=f"Client error: {str(e)}",
                method="html_extractor",
                extraction_time=asyncio.get_event_loop().time() - start_time
            )

        except Exception as e:
            self.logger.error(f"Unexpected error for {domain}: {str(e)}")
            return self.create_error_result(
                domain=domain,
                error_message=f"Unexpected error: {str(e)}",
                method="html_extractor",
                extraction_time=asyncio.get_event_loop().time() - start_time
            )

        finally:
            if close_session:
                await session.close()

    def _construct_url(self, domain: str) -> str:
        """Construct a proper URL from domain."""
        domain = domain.strip()
        if not domain.startswith(('http://', 'https://')):
            # Default to HTTPS for security
            domain = f'https://{domain}'
        return domain

    def _is_valid_response(self, status_code: int, content_type: str) -> bool:
        """Check if the response is valid for HTML parsing."""
        # Check status code
        if status_code >= 400:
            return False

        # Check content type
        html_types = ['text/html', 'text/xhtml', 'application/xhtml+xml']
        return any(html_type in content_type for html_type in html_types)

    async def _read_content_safely(self, response: aiohttp.ClientResponse) -> Optional[str]:
        """Safely read response content with size limits."""
        try:
            # Check content length if available
            content_length = response.headers.get('content-length')
            if content_length and int(content_length) > self.max_content_length:
                self.logger.warning(f"Content too large: {content_length} bytes")
                return None

            # Read content
            content = await response.text()

            # Double-check content length
            if len(content.encode('utf-8')) > self.max_content_length:
                self.logger.warning(f"Content exceeds size limit after reading")
                return None

            return content

        except Exception as e:
            self.logger.error(f"Error reading content: {str(e)}")
            return None

    def _extract_from_html(self, content: str, base_url: str) -> Tuple[Optional[str], Optional[str]]:
        """
        Extract title and description from HTML content.

        Args:
            content: HTML content
            base_url: Base URL for resolving relative URLs

        Returns:
            Tuple of (title, description)
        """
        try:
            # Parse HTML
            tree = html.fromstring(content)

            # Extract title
            title = self._extract_title(tree)

            # Extract description
            description = self._extract_description(tree)

            return title, description

        except etree.ParserError as e:
            self.logger.warning(f"HTML parsing error: {str(e)}")
            # Try parsing as fallback
            return self._extract_from_partial_html(content)

        except Exception as e:
            self.logger.error(f"Error extracting from HTML: {str(e)}")
            return None, None

    def _extract_title(self, tree) -> Optional[str]:
        """Extract title from HTML tree with multiple fallbacks."""
        # Primary: title tag
        title_elem = tree.find('.//title')
        if title_elem is not None and title_elem.text:
            title = title_elem.text.strip()
            if self.validate_title(title):
                return title

        # Secondary: h1 tag
        h1_elem = tree.find('.//h1')
        if h1_elem is not None and h1_elem.text:
            title = h1_elem.text.strip()
            if self.validate_title(title):
                return title

        # Tertiary: meta property og:title
        og_title = tree.xpath('.//meta[@property="og:title"]/@content')
        if og_title and og_title[0]:
            title = og_title[0].strip()
            if self.validate_title(title):
                return title

        # Quaternary: meta name title
        meta_title = tree.xpath('.//meta[@name="title"]/@content')
        if meta_title and meta_title[0]:
            title = meta_title[0].strip()
            if self.validate_title(title):
                return title

        return None

    def _extract_description(self, tree) -> Optional[str]:
        """Extract description from HTML tree with multiple fallbacks."""
        # Primary: meta name description
        meta_desc = tree.xpath('.//meta[@name="description"]/@content')
        if meta_desc and meta_desc[0]:
            desc = meta_desc[0].strip()
            if self.validate_description(desc):
                return desc

        # Secondary: meta property og:description
        og_desc = tree.xpath('.//meta[@property="og:description"]/@content')
        if og_desc and og_desc[0]:
            desc = og_desc[0].strip()
            if self.validate_description(desc):
                return desc

        # Tertiary: meta name twitter:description
        twitter_desc = tree.xpath('.//meta[@name="twitter:description"]/@content')
        if twitter_desc and twitter_desc[0]:
            desc = twitter_desc[0].strip()
            if self.validate_description(desc):
                return desc

        # Quaternary: First paragraph (as last resort)
        first_p = tree.xpath('.//p[1]//text()')
        if first_p:
            desc = ' '.join([text.strip() for text in first_p if text.strip()])
            if self.validate_description(desc):
                return desc

        return None

    def _extract_from_partial_html(self, content: str) -> Tuple[Optional[str], Optional[str]]:
        """Extract from potentially malformed HTML using regex fallbacks."""
        import re

        title = None
        description = None

        # Extract title using regex
        title_match = re.search(r'<title[^>]*>(.*?)</title>', content, re.IGNORECASE | re.DOTALL)
        if title_match:
            title = self.clean_text(title_match.group(1))
            if not self.validate_title(title):
                title = None

        # Extract description using regex
        desc_patterns = [
            r'<meta[^>]*name=["\']description["\'][^>]*content=["\']([^"\']+)["\']',
            r'<meta[^>]*content=["\']([^"\']+)["\'][^>]*name=["\']description["\']',
            r'<meta[^>]*property=["\']og:description["\'][^>]*content=["\']([^"\']+)["\']',
            r'<meta[^>]*content=["\']([^"\']+)["\'][^>]*property=["\']og:description["\']'
        ]

        for pattern in desc_patterns:
            desc_match = re.search(pattern, content, re.IGNORECASE)
            if desc_match:
                desc = self.clean_text(desc_match.group(1))
                if self.validate_description(desc):
                    description = desc
                    break

        return title, description
"""
Meta tag extractor focusing on OpenGraph, Twitter Cards, and structured data.
"""

import asyncio
import aiohttp
import json
from typing import Dict, Optional, Tuple, List, Any
from lxml import html, etree
import re
import logging

from .base_extractor import BaseExtractor, ExtractionResult

logger = logging.getLogger(__name__)


class MetaExtractor(BaseExtractor):
    """Specialized meta tag extractor for OpenGraph, Twitter Cards, and structured data."""

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
        Extract meta information focusing on structured meta tags.

        Args:
            domain: The domain to extract from
            **kwargs: Additional arguments

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
            self.logger.debug(f"Meta extracting from: {url}")

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
                        method="meta_extractor",
                        extraction_time=asyncio.get_event_loop().time() - start_time,
                        status_code=response.status
                    )

                # Read content with size limit
                content = await self._read_content_safely(response)
                if not content:
                    return self.create_error_result(
                        domain=domain,
                        error_message="No content received",
                        method="meta_extractor",
                        extraction_time=asyncio.get_event_loop().time() - start_time,
                        status_code=response.status
                    )

                # Extract meta information using specialized methods
                title, description = self._extract_structured_meta(content)

                extraction_time = asyncio.get_event_loop().time() - start_time

                if title or description:
                    self.logger.debug(f"Meta extraction successful for {domain}")
                    return self.create_success_result(
                        domain=domain,
                        title=title,
                        description=description,
                        method="meta_extractor",
                        extraction_time=extraction_time,
                        status_code=status_code
                    )
                else:
                    return self.create_error_result(
                        domain=domain,
                        error_message="No structured meta information found",
                        method="meta_extractor",
                        extraction_time=extraction_time,
                        status_code=status_code
                    )

        except asyncio.TimeoutError:
            self.logger.warning(f"Timeout for domain {domain}")
            return self.create_error_result(
                domain=domain,
                error_message="Request timeout",
                method="meta_extractor",
                extraction_time=asyncio.get_event_loop().time() - start_time
            )

        except aiohttp.ClientError as e:
            self.logger.warning(f"Client error for {domain}: {str(e)}")
            return self.create_error_result(
                domain=domain,
                error_message=f"Client error: {str(e)}",
                method="meta_extractor",
                extraction_time=asyncio.get_event_loop().time() - start_time
            )

        except Exception as e:
            self.logger.error(f"Unexpected error for {domain}: {str(e)}")
            return self.create_error_result(
                domain=domain,
                error_message=f"Unexpected error: {str(e)}",
                method="meta_extractor",
                extraction_time=asyncio.get_event_loop().time() - start_time
            )

        finally:
            if close_session:
                await session.close()

    def _construct_url(self, domain: str) -> str:
        """Construct a proper URL from domain."""
        domain = domain.strip()
        if not domain.startswith(('http://', 'https://')):
            domain = f'https://{domain}'
        return domain

    def _is_valid_response(self, status_code: int, content_type: str) -> bool:
        """Check if the response is valid for HTML parsing."""
        if status_code >= 400:
            return False

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

    def _extract_structured_meta(self, content: str) -> Tuple[Optional[str], Optional[str]]:
        """
        Extract meta information focusing on structured data.

        Args:
            content: HTML content

        Returns:
            Tuple of (title, description)
        """
        try:
            # Parse HTML
            tree = html.fromstring(content)

            # Extract with priority on structured data
            title = self._extract_structured_title(tree)
            description = self._extract_structured_description(tree)

            # Fallback to regular meta tags if structured data doesn't work
            if not title:
                title = self._extract_fallback_title(tree)
            if not description:
                description = self._extract_fallback_description(tree)

            # Final fallback to JSON-LD structured data
            if not title or not description:
                json_title, json_desc = self._extract_json_ld(content)
                if not title:
                    title = json_title
                if not description:
                    description = json_desc

            return title, description

        except Exception as e:
            self.logger.error(f"Error extracting structured meta: {str(e)}")
            # Try regex fallback
            return self._extract_with_regex(content)

    def _extract_structured_title(self, tree) -> Optional[str]:
        """Extract title from structured meta tags."""
        # Priority 1: OpenGraph title
        og_title = tree.xpath('.//meta[@property="og:title"]/@content')
        if og_title and og_title[0]:
            title = og_title[0].strip()
            if self.validate_title(title):
                return title

        # Priority 2: Twitter title
        twitter_title = tree.xpath('.//meta[@name="twitter:title"]/@content')
        if twitter_title and twitter_title[0]:
            title = twitter_title[0].strip()
            if self.validate_title(title):
                return title

        # Priority 3: Schema.org name
        schema_name = tree.xpath('.//meta[@itemprop="name"]/@content')
        if schema_name and schema_name[0]:
            title = schema_name[0].strip()
            if self.validate_title(title):
                return title

        return None

    def _extract_structured_description(self, tree) -> Optional[str]:
        """Extract description from structured meta tags."""
        # Priority 1: OpenGraph description
        og_desc = tree.xpath('.//meta[@property="og:description"]/@content')
        if og_desc and og_desc[0]:
            desc = og_desc[0].strip()
            if self.validate_description(desc):
                return desc

        # Priority 2: Twitter description
        twitter_desc = tree.xpath('.//meta[@name="twitter:description"]/@content')
        if twitter_desc and twitter_desc[0]:
            desc = twitter_desc[0].strip()
            if self.validate_description(desc):
                return desc

        # Priority 3: Schema.org description
        schema_desc = tree.xpath('.//meta[@itemprop="description"]/@content')
        if schema_desc and schema_desc[0]:
            desc = schema_desc[0].strip()
            if self.validate_description(desc):
                return desc

        return None

    def _extract_fallback_title(self, tree) -> Optional[str]:
        """Extract title using standard fallbacks."""
        # Standard title tag
        title_elem = tree.find('.//title')
        if title_elem is not None and title_elem.text:
            title = title_elem.text.strip()
            if self.validate_title(title):
                return title

        # h1 tag
        h1_elem = tree.find('.//h1')
        if h1_elem is not None and h1_elem.text:
            title = h1_elem.text.strip()
            if self.validate_title(title):
                return title

        return None

    def _extract_fallback_description(self, tree) -> Optional[str]:
        """Extract description using standard fallbacks."""
        # Standard meta description
        meta_desc = tree.xpath('.//meta[@name="description"]/@content')
        if meta_desc and meta_desc[0]:
            desc = meta_desc[0].strip()
            if self.validate_description(desc):
                return desc

        return None

    def _extract_json_ld(self, content: str) -> Tuple[Optional[str], Optional[str]]:
        """Extract information from JSON-LD structured data."""
        try:
            # Find all JSON-LD script tags
            json_pattern = r'<script[^>]*type=["\']application/ld\+json["\'][^>]*>(.*?)</script>'
            matches = re.findall(json_pattern, content, re.IGNORECASE | re.DOTALL)

            title = None
            description = None

            for match in matches:
                try:
                    # Parse JSON
                    data = json.loads(match.strip())

                    # Handle both single objects and arrays
                    if isinstance(data, list):
                        items = data
                    else:
                        items = [data]

                    for item in items:
                        if isinstance(item, dict):
                            # Try to extract title
                            if not title:
                                possible_titles = [
                                    item.get('name'),
                                    item.get('headline'),
                                    item.get('title')
                                ]
                                for possible_title in possible_titles:
                                    if possible_title and self.validate_title(str(possible_title)):
                                        title = str(possible_title)
                                        break

                            # Try to extract description
                            if not description:
                                possible_descriptions = [
                                    item.get('description'),
                                    item.get('about'),
                                    item.get('abstract')
                                ]
                                for possible_desc in possible_descriptions:
                                    if possible_desc and self.validate_description(str(possible_desc)):
                                        description = str(possible_desc)
                                        break

                except json.JSONDecodeError:
                    continue

            return title, description

        except Exception as e:
            self.logger.error(f"Error extracting JSON-LD: {str(e)}")
            return None, None

    def _extract_with_regex(self, content: str) -> Tuple[Optional[str], Optional[str]]:
        """Extract using regex as final fallback."""
        title = None
        description = None

        try:
            # Extract title using regex
            title_patterns = [
                r'<meta[^>]*property=["\']og:title["\'][^>]*content=["\']([^"\']+)["\']',
                r'<meta[^>]*name=["\']twitter:title["\'][^>]*content=["\']([^"\']+)["\']',
                r'<title[^>]*>(.*?)</title>'
            ]

            for pattern in title_patterns:
                match = re.search(pattern, content, re.IGNORECASE | re.DOTALL)
                if match:
                    title_text = self.clean_text(match.group(1))
                    if self.validate_title(title_text):
                        title = title_text
                        break

            # Extract description using regex
            desc_patterns = [
                r'<meta[^>]*property=["\']og:description["\'][^>]*content=["\']([^"\']+)["\']',
                r'<meta[^>]*name=["\']twitter:description["\'][^>]*content=["\']([^"\']+)["\']',
                r'<meta[^>]*name=["\']description["\'][^>]*content=["\']([^"\']+)["\']'
            ]

            for pattern in desc_patterns:
                match = re.search(pattern, content, re.IGNORECASE)
                if match:
                    desc_text = self.clean_text(match.group(1))
                    if self.validate_description(desc_text):
                        description = desc_text
                        break

        except Exception as e:
            self.logger.error(f"Regex extraction error: {str(e)}")

        return title, description
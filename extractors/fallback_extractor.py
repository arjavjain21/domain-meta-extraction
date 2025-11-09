"""
Fallback extractor using last-resort methods and content analysis.
"""

import asyncio
import aiohttp
from typing import Dict, Optional, Tuple, Any
from bs4 import BeautifulSoup
import re
import logging
from urllib.parse import urljoin, urlparse

from .base_extractor import BaseExtractor, ExtractionResult

logger = logging.getLogger(__name__)


class FallbackExtractor(BaseExtractor):
    """Fallback extractor using alternative methods and content analysis."""

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
        Extract meta information using fallback methods.

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
            # Try multiple fallback approaches
            title, description, status_code = await self._try_multiple_approaches(session, domain)

            extraction_time = asyncio.get_event_loop().time() - start_time

            if title or description:
                self.logger.debug(f"Fallback extraction successful for {domain}")
                return self.create_success_result(
                    domain=domain,
                    title=title,
                    description=description,
                    method="fallback_extractor",
                    extraction_time=extraction_time,
                    status_code=status_code
                )
            else:
                return self.create_error_result(
                    domain=domain,
                    error_message="All fallback methods failed",
                    method="fallback_extractor",
                    extraction_time=extraction_time,
                    status_code=status_code
                )

        except Exception as e:
            self.logger.error(f"Fallback extraction error for {domain}: {str(e)}")
            return self.create_error_result(
                domain=domain,
                error_message=f"Fallback error: {str(e)}",
                method="fallback_extractor",
                extraction_time=asyncio.get_event_loop().time() - start_time
            )

        finally:
            if close_session:
                await session.close()

    async def _try_multiple_approaches(self, session: aiohttp.ClientSession, domain: str) -> Tuple[Optional[str], Optional[str], Optional[int]]:
        """Try multiple fallback approaches to extract information."""

        # Approach 1: Try with BeautifulSoup (different parser)
        title, desc, status = await self._try_beautifulsoup(session, domain)
        if title or desc:
            return title, desc, status

        # Approach 2: Try HTTP instead of HTTPS (if original was HTTPS)
        if domain.startswith('https://'):
            http_domain = domain.replace('https://', 'http://')
            title, desc, status = await self._try_simple_request(session, http_domain)
            if title or desc:
                return title, desc, status

        # Approach 3: Try with www prefix (if not present)
        if not domain.startswith('www.') and not domain.startswith('http://www.') and not domain.startswith('https://www.'):
            www_domain = domain
            if www_domain.startswith('https://'):
                www_domain = www_domain.replace('https://', 'https://www.')
            elif www_domain.startswith('http://'):
                www_domain = www_domain.replace('http://', 'http://www.')
            else:
                www_domain = f'https://www.{www_domain}'

            title, desc, status = await self._try_simple_request(session, www_domain)
            if title or desc:
                return title, desc, status

        # Approach 4: Try without www prefix (if present)
        if 'www.' in domain:
            no_www_domain = domain.replace('www.', '')
            title, desc, status = await self._try_simple_request(session, no_www_domain)
            if title or desc:
                return title, desc, status

        # Approach 5: Try to infer from URL/Domain as last resort
        inferred_title = self._infer_title_from_domain(domain)
        inferred_desc = self._infer_description_from_domain(domain)

        return inferred_title, inferred_desc, None

    async def _try_beautifulsoup(self, session: aiohttp.ClientSession, domain: str) -> Tuple[Optional[str], Optional[str], Optional[int]]:
        """Try extraction with BeautifulSoup."""
        try:
            url = self._construct_url(domain)

            async with session.get(
                url,
                allow_redirects=self.follow_redirects,
                max_redirects=self.max_redirects
            ) as response:
                status_code = response.status
                content = await self._read_content_safely(response)

                if not content:
                    return None, None, status_code

                # Parse with BeautifulSoup
                soup = BeautifulSoup(content, 'html.parser')

                # Extract title
                title = self._extract_title_with_soup(soup)

                # Extract description
                description = self._extract_description_with_soup(soup)

                # Validate results
                if title and not self.validate_title(title):
                    title = None
                if description and not self.validate_description(description):
                    description = None

                return title, description, status_code

        except Exception as e:
            self.logger.debug(f"BeautifulSoup extraction failed: {str(e)}")
            return None, None, None

    async def _try_simple_request(self, session: aiohttp.ClientSession, domain: str) -> Tuple[Optional[str], Optional[str], Optional[int]]:
        """Try a simple HTTP request with minimal parsing."""
        try:
            url = self._construct_url(domain)

            # Use simpler headers to avoid being blocked
            simple_headers = {
                'User-Agent': 'Mozilla/5.0 (compatible; MetaBot/1.0)',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
            }

            async with session.get(
                url,
                headers=simple_headers,
                allow_redirects=True,
                max_redirects=5
            ) as response:
                status_code = response.status
                content = await self._read_content_safely(response)

                if not content:
                    return None, None, status_code

                # Use regex extraction
                title, description = self._extract_with_advanced_regex(content, url)

                return title, description, status_code

        except Exception as e:
            self.logger.debug(f"Simple request extraction failed: {str(e)}")
            return None, None, None

    def _construct_url(self, domain: str) -> str:
        """Construct a proper URL from domain."""
        domain = domain.strip()
        if not domain.startswith(('http://', 'https://')):
            domain = f'https://{domain}'
        return domain

    async def _read_content_safely(self, response: aiohttp.ClientResponse) -> Optional[str]:
        """Safely read response content."""
        try:
            content = await response.text()
            if len(content.encode('utf-8')) > self.max_content_length:
                return None
            return content
        except Exception:
            return None

    def _extract_title_with_soup(self, soup: BeautifulSoup) -> Optional[str]:
        """Extract title using BeautifulSoup."""
        # Try title tag
        title_tag = soup.find('title')
        if title_tag and title_tag.string:
            title = title_tag.string.strip()
            if self.validate_title(title):
                return title

        # Try h1
        h1_tag = soup.find('h1')
        if h1_tag and h1_tag.string:
            title = h1_tag.string.strip()
            if self.validate_title(title):
                return title

        # Try meta tags
        for meta_type in ['og:title', 'twitter:title']:
            meta_tag = soup.find('meta', property=meta_type) or soup.find('meta', attrs={'name': meta_type})
            if meta_tag and meta_tag.get('content'):
                title = meta_tag['content'].strip()
                if self.validate_title(title):
                    return title

        return None

    def _extract_description_with_soup(self, soup: BeautifulSoup) -> Optional[str]:
        """Extract description using BeautifulSoup."""
        # Try meta description
        meta_desc = soup.find('meta', attrs={'name': 'description'})
        if meta_desc and meta_desc.get('content'):
            desc = meta_desc['content'].strip()
            if self.validate_description(desc):
                return desc

        # Try OpenGraph description
        og_desc = soup.find('meta', property='og:description')
        if og_desc and og_desc.get('content'):
            desc = og_desc['content'].strip()
            if self.validate_description(desc):
                return desc

        # Try first paragraph
        first_p = soup.find('p')
        if first_p and first_p.string:
            desc = first_p.string.strip()
            if self.validate_description(desc):
                return desc

        return None

    def _extract_with_advanced_regex(self, content: str, url: str) -> Tuple[Optional[str], Optional[str]]:
        """Extract using advanced regex patterns."""
        title = None
        description = None

        try:
            # Advanced title patterns
            title_patterns = [
                # Standard title tag with various quotes
                r'<title[^>]*>([^{<}]*)</title>',
                # Meta property patterns
                r'<meta[^>]*property=["\']og:title["\'][^>]*content=["\']([^"\']{3,200})["\']',
                r'<meta[^>]*name=["\']twitter:title["\'][^>]*content=["\']([^"\']{3,200})["\']',
                # H1 patterns
                r'<h1[^>]*>([^{<}]*)</h1>',
                # Alternative title meta
                r'<meta[^>]*name=["\']title["\'][^>]*content=["\']([^"\']{3,200})["\']'
            ]

            for pattern in title_patterns:
                matches = re.findall(pattern, content, re.IGNORECASE | re.DOTALL)
                for match in matches:
                    title_text = self.clean_text(match)
                    if self.validate_title(title_text):
                        title = title_text
                        break
                if title:
                    break

            # Advanced description patterns
            desc_patterns = [
                # Standard meta description
                r'<meta[^>]*name=["\']description["\'][^>]*content=["\']([^"\']{10,500})["\']',
                # OpenGraph description
                r'<meta[^>]*property=["\']og:description["\'][^>]*content=["\']([^"\']{10,500})["\']',
                # Twitter description
                r'<meta[^>]*name=["\']twitter:description["\'][^>]*content=["\']([^"\']{10,500})["\']',
                # Schema.org description
                r'<meta[^>]*itemprop=["\']description["\'][^>]*content=["\']([^"\']{10,500})["\']'
            ]

            for pattern in desc_patterns:
                matches = re.findall(pattern, content, re.IGNORECASE)
                for match in matches:
                    desc_text = self.clean_text(match)
                    if self.validate_description(desc_text):
                        description = desc_text
                        break
                if description:
                    break

            # If still no description, try to extract from first meaningful paragraph
            if not description:
                paragraph_pattern = r'<p[^>]*>([^{<}]{20,500})</p>'
                paragraphs = re.findall(paragraph_pattern, content, re.IGNORECASE | re.DOTALL)

                for paragraph in paragraphs[:3]:  # Check first 3 paragraphs
                    para_text = self.clean_text(paragraph)
                    if self.validate_description(para_text):
                        description = para_text
                        break

        except Exception as e:
            self.logger.debug(f"Advanced regex extraction error: {str(e)}")

        return title, description

    def _infer_title_from_domain(self, domain: str) -> Optional[str]:
        """Infer title from domain name."""
        try:
            # Extract domain name without TLD
            parsed = urlparse(domain if domain.startswith(('http://', 'https://')) else f'https://{domain}')
            domain_name = parsed.netloc

            # Remove www prefix and TLD
            domain_name = domain_name.replace('www.', '')
            parts = domain_name.split('.')

            if len(parts) >= 2:
                # Take the main part (second-to-last part for most domains)
                main_part = parts[-2]
            else:
                main_part = parts[0] if parts else domain_name

            # Clean and format
            title = main_part.replace('-', ' ').replace('_', ' ').title()

            if self.validate_title(title):
                return title

        except Exception:
            pass

        return None

    def _infer_description_from_domain(self, domain: str) -> Optional[str]:
        """Infer description from domain name."""
        try:
            title = self._infer_title_from_domain(domain)
            if title:
                # Create a generic but reasonable description
                description = f"Website and online services for {title}"
                if self.validate_description(description):
                    return description

        except Exception:
            pass

        return None
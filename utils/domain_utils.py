"""
Domain utility functions for normalization and validation.
"""

import re
from typing import Optional, List
from urllib.parse import urlparse
import logging

logger = logging.getLogger(__name__)


class DomainUtils:
    """Utility class for domain operations."""

    @staticmethod
    def normalize_domain(domain: str) -> Optional[str]:
        """
        Normalize a domain name.

        Args:
            domain: The domain to normalize

        Returns:
            Normalized domain or None if invalid
        """
        if not domain:
            return None

        try:
            # Remove whitespace
            domain = domain.strip()

            # Remove URL scheme if present
            if domain.startswith(('http://', 'https://')):
                parsed = urlparse(domain)
                domain = parsed.netloc
            else:
                # Remove any remaining URL parts
                parsed = urlparse(f'http://{domain}')
                domain = parsed.netloc

            # Remove www prefix for consistency (optional)
            # domain = DomainUtils.remove_www_prefix(domain)

            # Convert to lowercase
            domain = domain.lower()

            # Remove port number if present
            domain = domain.split(':')[0]

            # Remove trailing dots
            domain = domain.rstrip('.')

            # Validate the domain
            if DomainUtils.is_valid_domain(domain):
                return domain
            else:
                logger.warning(f"Invalid domain format: {domain}")
                return None

        except Exception as e:
            logger.error(f"Error normalizing domain '{domain}': {str(e)}")
            return None

    @staticmethod
    def is_valid_domain(domain: str) -> bool:
        """
        Validate if a domain name is properly formatted.

        Args:
            domain: The domain to validate

        Returns:
            True if valid, False otherwise
        """
        if not domain:
            return False

        # Basic domain regex pattern
        domain_pattern = re.compile(
            r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$'
        )

        # Check basic pattern
        if not domain_pattern.match(domain):
            return False

        # Additional checks
        parts = domain.split('.')

        # Must have at least 2 parts (e.g., example.com)
        if len(parts) < 2:
            return False

        # TLD must be at least 2 characters
        if len(parts[-1]) < 2:
            return False

        # Domain part must not be too long
        if len(domain) > 253:
            return False

        # Each part must not be too long
        for part in parts:
            if len(part) > 63:
                return False
            if part.startswith('-') or part.endswith('-'):
                return False

        return True

    @staticmethod
    def extract_domain(url: str) -> Optional[str]:
        """
        Extract domain from a full URL.

        Args:
            url: The URL to extract domain from

        Returns:
            Extracted domain or None if invalid
        """
        try:
            if not url:
                return None

            # Add scheme if missing
            if not url.startswith(('http://', 'https://')):
                url = f'http://{url}'

            parsed = urlparse(url)
            domain = parsed.netloc

            if domain and DomainUtils.is_valid_domain(domain):
                return domain

            return None

        except Exception as e:
            logger.error(f"Error extracting domain from '{url}': {str(e)}")
            return None

    @staticmethod
    def remove_www_prefix(domain: str) -> str:
        """
        Remove www prefix from domain.

        Args:
            domain: The domain to process

        Returns:
            Domain without www prefix
        """
        if domain.startswith('www.'):
            return domain[4:]
        return domain

    @staticmethod
    def add_www_prefix(domain: str) -> str:
        """
        Add www prefix to domain if not present.

        Args:
            domain: The domain to process

        Returns:
            Domain with www prefix
        """
        if not domain.startswith('www.'):
            return f'www.{domain}'
        return domain

    @staticmethod
    def get_tld(domain: str) -> Optional[str]:
        """
        Get the top-level domain from a domain.

        Args:
            domain: The domain to process

        Returns:
            TLD or None if invalid
        """
        try:
            parts = domain.split('.')
            if len(parts) >= 2:
                return parts[-1]
            return None
        except Exception:
            return None

    @staticmethod
    def get_root_domain(domain: str) -> Optional[str]:
        """
        Get the root domain (domain + TLD) from a subdomain.

        Args:
            domain: The domain to process

        Returns:
            Root domain or None if invalid
        """
        try:
            parts = domain.split('.')
            if len(parts) >= 2:
                return '.'.join(parts[-2:])
            return None
        except Exception:
            return None

    @staticmethod
    def is_subdomain(domain: str, root_domain: str) -> bool:
        """
        Check if a domain is a subdomain of another domain.

        Args:
            domain: The domain to check
            root_domain: The potential root domain

        Returns:
            True if domain is a subdomain of root_domain
        """
        try:
            domain_root = DomainUtils.get_root_domain(domain)
            return domain_root == root_domain
        except Exception:
            return False

    @staticmethod
    def generate_variants(domain: str) -> List[str]:
        """
        Generate common variants of a domain for fallback attempts.

        Args:
            domain: The base domain

        Returns:
            List of domain variants
        """
        variants = []

        try:
            # Original domain
            if domain:
                variants.append(domain)

            # Without www
            if domain.startswith('www.'):
                variants.append(domain[4:])

            # With www
            if not domain.startswith('www.'):
                variants.append(f'www.{domain}')

            # HTTP and HTTPS versions
            http_variants = []
            for variant in variants.copy():
                if not variant.startswith(('http://', 'https://')):
                    http_variants.append(f'https://{variant}')
                    http_variants.append(f'http://{variant}')

            variants.extend(http_variants)

            # Remove duplicates while preserving order
            seen = set()
            unique_variants = []
            for variant in variants:
                if variant not in seen:
                    seen.add(variant)
                    unique_variants.append(variant)

            return unique_variants

        except Exception as e:
            logger.error(f"Error generating variants for '{domain}': {str(e)}")
            return [domain] if domain else []

    @staticmethod
    def sanitize_domain_list(domains: List[str]) -> List[str]:
        """
        Sanitize and normalize a list of domains.

        Args:
            domains: List of domains to sanitize

        Returns:
            List of normalized, valid domains
        """
        sanitized = []

        for domain in domains:
            if not domain:
                continue

            normalized = DomainUtils.normalize_domain(domain)
            if normalized and normalized not in sanitized:
                sanitized.append(normalized)

        return sanitized

    @staticmethod
    def categorize_domain(domain: str) -> str:
        """
        Categorize a domain type for better processing decisions.

        Args:
            domain: The domain to categorize

        Returns:
            Category string (e.g., 'commercial', 'organization', 'educational', etc.)
        """
        try:
            tld = DomainUtils.get_tld(domain)

            if not tld:
                return 'unknown'

            # Common TLD categories
            commercial_tlds = ['.com', '.biz', '.store', '.shop', '.online', '.site']
            organization_tlds = ['.org', '.ngo', '.foundation']
            educational_tlds = ['.edu', '.ac', '.school']
            government_tlds = ['.gov', '.mil']
            network_tlds = ['.net', '.network']
            technology_tlds = ['.tech', '.io', '.ai', '.dev']
            geographic_tlds = ['.us', '.uk', '.ca', '.de', '.fr', '.jp', '.au']

            tld_lower = f'.{tld.lower()}'

            if tld_lower in commercial_tlds:
                return 'commercial'
            elif tld_lower in organization_tlds:
                return 'organization'
            elif tld_lower in educational_tlds:
                return 'educational'
            elif tld_lower in government_tlds:
                return 'government'
            elif tld_lower in network_tlds:
                return 'network'
            elif tld_lower in technology_tlds:
                return 'technology'
            elif tld_lower in geographic_tlds:
                return 'geographic'
            else:
                return 'other'

        except Exception:
            return 'unknown'
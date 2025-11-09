"""
Base extractor interface and common functionality.
"""

from abc import ABC, abstractmethod
from typing import Dict, Optional, Tuple, Any
from dataclasses import dataclass
from datetime import datetime
import logging

logger = logging.getLogger(__name__)


@dataclass
class ExtractionResult:
    """Result of a meta extraction attempt."""
    domain: str
    title: Optional[str] = None
    description: Optional[str] = None
    method: str = "unknown"
    status_code: Optional[int] = None
    extraction_time: Optional[float] = None
    error_message: Optional[str] = None
    success: bool = False

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for CSV output."""
        return {
            'domain': self.domain,
            'meta_title': self.title or '',
            'meta_description': self.description or '',
            'extraction_method': self.method,
            'status_code': self.status_code or 0,
            'extraction_time': self.extraction_time or 0,
            'error_message': self.error_message or ''
        }


class BaseExtractor(ABC):
    """Base class for all meta extractors."""

    def __init__(self, config: Dict[str, Any]):
        """
        Initialize the extractor.

        Args:
            config: Configuration dictionary
        """
        self.config = config
        self.logger = logging.getLogger(self.__class__.__name__)

        # Extract common settings
        self.min_title_length = config.get('extraction', {}).get('min_title_length', 3)
        self.max_title_length = config.get('extraction', {}).get('max_title_length', 200)
        self.min_description_length = config.get('extraction', {}).get('min_description_length', 10)
        self.max_description_length = config.get('extraction', {}).get('max_description_length', 500)
        self.max_content_length = config.get('extraction', {}).get('max_content_length', 1048576)

    @abstractmethod
    async def extract(self, domain: str, **kwargs) -> ExtractionResult:
        """
        Extract meta information from a domain.

        Args:
            domain: The domain to extract from
            **kwargs: Additional arguments

        Returns:
            ExtractionResult with the extracted information
        """
        pass

    def validate_title(self, title: str) -> bool:
        """
        Validate if a title meets quality criteria.

        Args:
            title: The title to validate

        Returns:
            True if title is valid, False otherwise
        """
        if not title:
            return False

        title = title.strip()
        length = len(title)

        return (self.min_title_length <= length <= self.max_title_length and
                not title.isdigit() and
                not title.isspace())

    def validate_description(self, description: str) -> bool:
        """
        Validate if a description meets quality criteria.

        Args:
            description: The description to validate

        Returns:
            True if description is valid, False otherwise
        """
        if not description:
            return False

        description = description.strip()
        length = len(description)

        return (self.min_description_length <= length <= self.max_description_length and
                not description.isdigit() and
                not description.isspace())

    def clean_text(self, text: str) -> str:
        """
        Clean and normalize text.

        Args:
            text: The text to clean

        Returns:
            Cleaned text
        """
        if not text:
            return ""

        # Remove extra whitespace and normalize
        text = ' '.join(text.split())

        # Remove common unwanted characters/patterns
        unwanted_patterns = ['\n', '\r', '\t']
        for pattern in unwanted_patterns:
            text = text.replace(pattern, ' ')

        # Remove multiple spaces
        while '  ' in text:
            text = text.replace('  ', ' ')

        return text.strip()

    def create_success_result(self, domain: str, title: str, description: str,
                            method: str, extraction_time: float,
                            status_code: int = 200) -> ExtractionResult:
        """
        Create a successful extraction result.

        Args:
            domain: The domain
            title: Extracted title
            description: Extracted description
            method: Extraction method used
            extraction_time: Time taken for extraction
            status_code: HTTP status code

        Returns:
            ExtractionResult with success=True
        """
        return ExtractionResult(
            domain=domain,
            title=self.clean_text(title) if title else None,
            description=self.clean_text(description) if description else None,
            method=method,
            status_code=status_code,
            extraction_time=extraction_time,
            success=True
        )

    def create_error_result(self, domain: str, error_message: str,
                          method: str, extraction_time: float,
                          status_code: Optional[int] = None) -> ExtractionResult:
        """
        Create an error extraction result.

        Args:
            domain: The domain
            error_message: Error description
            method: Extraction method attempted
            extraction_time: Time taken for extraction attempt
            status_code: HTTP status code if available

        Returns:
            ExtractionResult with success=False
        """
        return ExtractionResult(
            domain=domain,
            method=method,
            status_code=status_code,
            extraction_time=extraction_time,
            error_message=error_message,
            success=False
        )

    async def __aenter__(self):
        """Async context manager entry."""
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        pass
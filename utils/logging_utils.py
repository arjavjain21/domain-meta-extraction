"""
Enhanced logging utilities for the domain extractor.
"""

import logging
import logging.handlers
import sys
import traceback
from typing import Optional, Dict, Any
from pathlib import Path
import colorlog
from datetime import datetime


class ColoredFormatter(colorlog.ColoredFormatter):
    """Enhanced colored formatter with better formatting."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.use_colors = kwargs.get('use_colors', True)

    def format(self, record):
        """Format log record with enhanced information."""
        # Add custom fields
        if hasattr(record, 'domain'):
            record.domain_info = f"[{record.domain}] "
        else:
            record.domain_info = ""

        if hasattr(record, 'extraction_time'):
            record.time_info = f"({record.extraction_time:.2f}s) "
        else:
            record.time_info = ""

        # Call parent format
        formatted = super().format(record)

        # Remove color codes if colors disabled
        if not self.use_colors:
            formatted = colorlog.escape_codes(formatted)

        return formatted


class ExtractionLogger:
    """Specialized logger for extraction operations."""

    def __init__(self, name: str = "domain_extractor"):
        self.logger = logging.getLogger(name)
        self.logger.handlers.clear()
        self.setup_complete = False

    def setup(self, config: Dict[str, Any]) -> None:
        """
        Setup logging configuration.

        Args:
            config: Logging configuration dictionary
        """
        if self.setup_complete:
            return

        # Extract config
        level = config.get('level', 'INFO').upper()
        colored = config.get('colored', True)
        log_format = config.get('format', '%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        file_logging = config.get('file_logging', True)
        log_file = config.get('log_file', 'extraction.log')
        max_log_size = config.get('max_log_size', 50)  # MB

        # Set logger level
        self.logger.setLevel(getattr(logging, level))

        # Console handler
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(getattr(logging, level))

        if colored:
            console_formatter = ColoredFormatter(
                f"%(log_color)s{log_format}%(reset)s",
                datefmt='%H:%M:%S',
                use_colors=True,
                log_colors={
                    'DEBUG': 'cyan',
                    'INFO': 'green',
                    'WARNING': 'yellow',
                    'ERROR': 'red',
                    'CRITICAL': 'red,bg_white',
                }
            )
        else:
            console_formatter = logging.Formatter(log_format)

        console_handler.setFormatter(console_formatter)
        self.logger.addHandler(console_handler)

        # File handler
        if file_logging:
            log_path = Path(log_file)
            log_path.parent.mkdir(parents=True, exist_ok=True)

            # Use rotating file handler
            file_handler = logging.handlers.RotatingFileHandler(
                log_path,
                maxBytes=max_log_size * 1024 * 1024,  # Convert MB to bytes
                backupCount=5,
                encoding='utf-8'
            )
            file_handler.setLevel(logging.DEBUG)  # Always log everything to file

            file_formatter = logging.Formatter(
                f"{log_format} (File: %(filename)s:%(lineno)d)"
            )
            file_handler.setFormatter(file_formatter)
            self.logger.addHandler(file_handler)

        self.setup_complete = True

    def log_extraction_start(self, domain: str) -> None:
        """Log the start of extraction for a domain."""
        self.logger.debug(f"Starting extraction for {domain}", extra={'domain': domain})

    def log_extraction_success(self, domain: str, method: str, extraction_time: float) -> None:
        """Log successful extraction."""
        self.logger.info(
            f"Successfully extracted from {domain} using {method}",
            extra={'domain': domain, 'extraction_time': extraction_time}
        )

    def log_extraction_error(self, domain: str, error: str, method: str = None) -> None:
        """Log extraction error."""
        method_info = f" using {method}" if method else ""
        self.logger.warning(
            f"Failed to extract from {domain}{method_info}: {error}",
            extra={'domain': domain}
        )

    def log_rate_limit_hit(self, domain: str) -> None:
        """Log rate limiting event."""
        self.logger.debug(f"Rate limited for {domain}", extra={'domain': domain})

    def log_retry_attempt(self, domain: str, attempt: int, max_attempts: int) -> None:
        """Log retry attempt."""
        self.logger.debug(
            f"Retry {attempt}/{max_attempts} for {domain}",
            extra={'domain': domain}
        )

    def log_pipeline_progress(self, processed: int, total: int, success_rate: float) -> None:
        """Log overall pipeline progress."""
        self.logger.info(
            f"Progress: {processed:,}/{total:,} domains ({success_rate:.1f}% success rate)"
        )

    def log_performance_stats(self, stats: Dict[str, Any]) -> None:
        """Log performance statistics."""
        self.logger.info("=== Performance Statistics ===")
        self.logger.info(f"Total processed: {stats.get('total_processed', 0):,}")
        self.logger.info(f"Successful: {stats.get('successful', 0):,}")
        self.logger.info(f"Failed: {stats.get('failed', 0):,}")

        if 'duration' in stats:
            duration = stats['duration']
            total = stats.get('total_processed', 0)
            self.logger.info(f"Duration: {duration:.1f} seconds")
            if total > 0:
                self.logger.info(f"Speed: {total/duration:.1f} domains/second")

    def log_exception(self, domain: str, exception: Exception) -> None:
        """Log exception with full traceback."""
        self.logger.error(
            f"Exception processing {domain}: {str(exception)}",
            extra={'domain': domain},
            exc_info=True
        )


class ErrorTracker:
    """Tracks and categorizes errors for analysis."""

    def __init__(self):
        self.errors: Dict[str, int] = {}
        self.domain_errors: Dict[str, list] = {}
        self.logger = logging.getLogger("error_tracker")

    def track_error(self, domain: str, error_type: str, error_message: str) -> None:
        """
        Track an error occurrence.

        Args:
            domain: Domain where error occurred
            error_type: Type of error
            error_message: Error message
        """
        # Count error type
        self.errors[error_type] = self.errors.get(error_type, 0) + 1

        # Track domain errors
        if domain not in self.domain_errors:
            self.domain_errors[domain] = []
        self.domain_errors[domain].append({
            'type': error_type,
            'message': error_message,
            'timestamp': datetime.now().isoformat()
        })

        self.logger.debug(f"Tracked error: {error_type} for {domain}")

    def get_error_summary(self) -> Dict[str, Any]:
        """Get error summary statistics."""
        total_errors = sum(self.errors.values())
        total_domains = len(self.domain_errors)

        if total_errors == 0:
            return {
                'total_errors': 0,
                'total_domains_affected': 0,
                'error_types': {},
                'most_common_error': None
            }

        # Find most common error
        most_common_error = max(self.errors.items(), key=lambda x: x[1])

        return {
            'total_errors': total_errors,
            'total_domains_affected': total_domains,
            'error_types': self.errors.copy(),
            'most_common_error': {
                'type': most_common_error[0],
                'count': most_common_error[1],
                'percentage': (most_common_error[1] / total_errors) * 100
            },
            'error_rate_by_domain': {
                domain: len(errors) for domain, errors in self.domain_errors.items()
            }
        }

    def get_domains_with_most_errors(self, limit: int = 10) -> list:
        """Get domains with the most errors."""
        sorted_domains = sorted(
            self.domain_errors.items(),
            key=lambda x: len(x[1]),
            reverse=True
        )
        return [
            {
                'domain': domain,
                'error_count': len(errors),
                'errors': errors
            }
            for domain, errors in sorted_domains[:limit]
        ]

    def save_error_report(self, output_path: str) -> None:
        """Save detailed error report to file."""
        import json

        report = {
            'summary': self.get_error_summary(),
            'top_problematic_domains': self.get_domains_with_most_errors(20),
            'all_errors': self.domain_errors,
            'generated_at': datetime.now().isoformat()
        }

        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)

        self.logger.info(f"Error report saved to {output_path}")


def setup_logging_from_config(config: Dict[str, Any]) -> ExtractionLogger:
    """
    Setup logging from configuration dictionary.

    Args:
        config: Configuration dictionary

    Returns:
        Configured ExtractionLogger instance
    """
    logging_config = config.get('logging', {})
    logger = ExtractionLogger()
    logger.setup(logging_config)
    return logger


def get_logger(name: str = None) -> logging.Logger:
    """
    Get a logger instance.

    Args:
        name: Logger name (optional)

    Returns:
        Logger instance
    """
    return logging.getLogger(name or "domain_extractor")


# Global error tracker instance
_error_tracker: Optional[ErrorTracker] = None


def get_error_tracker() -> ErrorTracker:
    """Get or create the global error tracker."""
    global _error_tracker
    if _error_tracker is None:
        _error_tracker = ErrorTracker()
    return _error_tracker


def track_error(domain: str, error_type: str, error_message: str) -> None:
    """Track an error using the global error tracker."""
    get_error_tracker().track_error(domain, error_type, error_message)


def log_function_call(func):
    """Decorator to log function calls."""
    def wrapper(*args, **kwargs):
        logger = get_logger(func.__module__)
        logger.debug(f"Calling {func.__name__} with args={args}, kwargs={kwargs}")
        try:
            result = func(*args, **kwargs)
            logger.debug(f"{func.__name__} completed successfully")
            return result
        except Exception as e:
            logger.error(f"{func.__name__} failed: {str(e)}")
            raise
    return wrapper


async def log_async_function_call(func):
    """Decorator to log async function calls."""
    async def wrapper(*args, **kwargs):
        logger = get_logger(func.__module__)
        logger.debug(f"Calling async {func.__name__} with args={args}, kwargs={kwargs}")
        try:
            result = await func(*args, **kwargs)
            logger.debug(f"Async {func.__name__} completed successfully")
            return result
        except Exception as e:
            logger.error(f"Async {func.__name__} failed: {str(e)}")
            raise
    return wrapper
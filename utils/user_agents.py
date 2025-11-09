"""
User agent rotation utilities for web scraping.
"""

import random
from typing import List, Dict, Optional
import logging

logger = logging.getLogger(__name__)


class UserAgentRotator:
    """Rotates user agents to avoid detection and blocking."""

    def __init__(self, user_agents: Optional[List[str]] = None):
        """
        Initialize user agent rotator.

        Args:
            user_agents: List of user agents to rotate through
        """
        if user_agents:
            self.user_agents = user_agents
        else:
            self.user_agents = self._get_default_user_agents()

        self.current_index = 0
        self.last_rotation = 0

    def _get_default_user_agents(self) -> List[str]:
        """Get default list of user agents."""
        return [
            # Chrome on Windows
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36",

            # Chrome on macOS
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",

            # Firefox on Windows
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:119.0) Gecko/20100101 Firefox/119.0",

            # Firefox on macOS
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:121.0) Gecko/20100101 Firefox/121.0",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:120.0) Gecko/20100101 Firefox/120.0",

            # Safari on macOS
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2.1 Safari/605.1.15",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1.2 Safari/605.1.15",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.6 Safari/605.1.15",

            # Edge on Windows
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36 Edg/119.0.0.0",

            # Mobile browsers
            "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2.1 Mobile/15E148 Safari/604.1",
            "Mozilla/5.0 (iPad; CPU OS 17_2_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2.1 Mobile/15E148 Safari/604.1",
            "Mozilla/5.0 (Linux; Android 14; SM-G998B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36",

            # Alternative browsers
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 OPR/106.0.0.0",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",

            # Bot-like but acceptable (use sparingly)
            "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
            "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)",
        ]

    def get_random_user_agent(self) -> str:
        """
        Get a random user agent from the list.

        Returns:
            Random user agent string
        """
        return random.choice(self.user_agents)

    def get_next_user_agent(self) -> str:
        """
        Get the next user agent in rotation.

        Returns:
            Next user agent string
        """
        user_agent = self.user_agents[self.current_index]
        self.current_index = (self.current_index + 1) % len(self.user_agents)
        return user_agent

    def get_user_agent_for_domain(self, domain: str) -> str:
        """
        Get a user agent based on domain characteristics.

        Args:
            domain: The target domain

        Returns:
            User agent string
        """
        # Use different user agents for different types of sites
        domain_lower = domain.lower()

        # Tech sites might be more tolerant of modern browsers
        tech_indicators = ['tech', 'dev', 'code', 'software', 'api', 'github']
        if any(indicator in domain_lower for indicator in tech_indicators):
            # Use modern Chrome or Firefox
            tech_agents = [ua for ua in self.user_agents if 'Chrome/120' in ua or 'Firefox/121' in ua]
            if tech_agents:
                return random.choice(tech_agents)

        # Educational/government sites might be more conservative
        edu_gov_indicators = ['.edu', '.gov', 'university', 'college', 'school']
        if any(indicator in domain_lower for indicator in edu_gov_indicators):
            # Use more common browsers
            common_agents = [
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0"
            ]
            return random.choice(common_agents)

        # Mobile sites
        mobile_indicators = ['m.', 'mobile', 'touch', 'app']
        if any(indicator in domain_lower for indicator in mobile_indicators):
            mobile_agents = [ua for ua in self.user_agents if 'Mobile' in ua or 'Android' in ua]
            if mobile_agents:
                return random.choice(mobile_agents)

        # Default: random selection
        return self.get_random_user_agent()

    def get_headers(self, domain: str = None, additional_headers: Optional[Dict] = None) -> Dict[str, str]:
        """
        Get complete HTTP headers including user agent.

        Args:
            domain: Target domain (for user agent selection)
            additional_headers: Additional headers to include

        Returns:
            Complete HTTP headers dictionary
        """
        # Select user agent
        if domain:
            user_agent = self.get_user_agent_for_domain(domain)
        else:
            user_agent = self.get_next_user_agent()

        # Base headers
        headers = {
            'User-Agent': user_agent,
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
            'Accept-Language': 'en-US,en;q=0.9,en-GB;q=0.8,en;q=0.7',
            'Accept-Encoding': 'gzip, deflate, br',
            'DNT': '1',  # Do Not Track
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
            'Sec-Fetch-Dest': 'document',
            'Sec-Fetch-Mode': 'navigate',
            'Sec-Fetch-Site': 'none',
            'Sec-Fetch-User': '?1',
            'Cache-Control': 'max-age=0'
        }

        # Add domain-specific headers
        if domain:
            domain_lower = domain.lower()

            # Some sites require specific headers
            if 'linkedin.com' in domain_lower:
                headers['sec-ch-ua'] = '"Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"'
                headers['sec-ch-ua-mobile'] = '?0'
                headers['sec-ch-ua-platform'] = '"Windows"'

            elif 'facebook.com' in domain_lower:
                headers['Accept'] = 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9'

            elif 'twitter.com' in domain_lower or 'x.com' in domain_lower:
                headers['Accept'] = 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9'

        # Add additional headers
        if additional_headers:
            headers.update(additional_headers)

        return headers

    def add_user_agent(self, user_agent: str) -> None:
        """
        Add a new user agent to the rotation.

        Args:
            user_agent: User agent string to add
        """
        if user_agent and user_agent not in self.user_agents:
            self.user_agents.append(user_agent)
            logger.info(f"Added new user agent: {user_agent[:50]}...")

    def remove_user_agent(self, user_agent: str) -> bool:
        """
        Remove a user agent from the rotation.

        Args:
            user_agent: User agent string to remove

        Returns:
            True if removed, False if not found
        """
        if user_agent in self.user_agents and len(self.user_agents) > 1:
            self.user_agents.remove(user_agent)
            logger.info(f"Removed user agent: {user_agent[:50]}...")
            return True
        return False

    def get_stats(self) -> Dict:
        """Get user agent rotator statistics."""
        return {
            'total_user_agents': len(self.user_agents),
            'current_index': self.current_index,
            'current_user_agent': self.user_agents[self.current_index] if self.user_agents else None
        }


def create_user_agent_rotator(config: Dict) -> UserAgentRotator:
    """
    Create a user agent rotator from configuration.

    Args:
        config: Configuration dictionary

    Returns:
        Configured user agent rotator
    """
    # Get user agents from config or use defaults
    user_agents = config.get('user_agents', {}).get('agents', [])
    rotate_user_agents = config.get('politeness', {}).get('rotate_user_agents', True)

    if rotate_user_agents and user_agents:
        return UserAgentRotator(user_agents)
    else:
        return UserAgentRotator()  # Use defaults


# Global user agent rotator instance
_global_rotator: Optional[UserAgentRotator] = None


def get_global_user_agent_rotator() -> UserAgentRotator:
    """Get or create the global user agent rotator."""
    global _global_rotator
    if _global_rotator is None:
        _global_rotator = UserAgentRotator()
    return _global_rotator


def get_random_headers(domain: str = None, additional_headers: Optional[Dict] = None) -> Dict[str, str]:
    """
    Get random headers using the global user agent rotator.

    Args:
        domain: Target domain
        additional_headers: Additional headers to include

    Returns:
        HTTP headers dictionary
    """
    return get_global_user_agent_rotator().get_headers(domain, additional_headers)
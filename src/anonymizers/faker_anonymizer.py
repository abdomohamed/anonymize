"""
Faker anonymizer - replaces PII with realistic fake data.

This strategy generates fake data that maintains the format and structure
of the original PII, useful for testing and development environments.
"""

from src.anonymizers.base_anonymizer import BaseAnonymizer
from src.models import PIIMatch


class FakerAnonymizer(BaseAnonymizer):
    """
    Faker anonymizer that generates realistic fake data.
    
    Examples:
        - john.doe@example.com -> jane.smith@example.org
        - 555-123-4567 -> 555-987-6543
        - John Doe -> Jane Smith
    """
    
    def __init__(self, config: dict):
        """
        Initialize Faker anonymizer.
        
        Args:
            config: Configuration dictionary with Faker options
        """
        super().__init__(config)
        
        # Faker configuration
        self.locale = self.get_config_option('locale', 'en_US')
        self.seed = self.get_config_option('seed', None)
        self.preserve_format = self.get_config_option('preserve_format', True)
        
        # Initialize Faker
        self.fake = None
        self._init_faker()
        
        # Cache for consistent replacements
        self._replacement_cache = {}
    
    def _init_faker(self) -> None:
        """Initialize Faker library."""
        try:
            from faker import Faker
            self.fake = Faker(self.locale)
            if self.seed is not None:
                Faker.seed(self.seed)
        except ImportError:
            print("Warning: Faker library not installed. FakerAnonymizer will be disabled.")
            self.fake = None
    
    def anonymize(self, match: PIIMatch, context: str = "") -> str:
        """
        Anonymize PII by generating fake data.
        
        Args:
            match: PIIMatch object containing the PII to replace
            context: Optional full text context
            
        Returns:
            Fake data string
        """
        if self.fake is None:
            # Fallback to redaction if Faker not available
            return f"[{match.pii_type}_FAKE]"
        
        # Check cache for consistent replacements
        cache_key = (match.pii_type, match.value)
        if cache_key in self._replacement_cache:
            return self._replacement_cache[cache_key]
        
        # Generate fake data based on PII type
        pii_type = match.pii_type
        
        if pii_type == "EMAIL":
            fake_value = self._fake_email(match.value)
        elif pii_type == "PHONE":
            fake_value = self._fake_phone(match.value)
        elif pii_type == "SSN":
            fake_value = self._fake_ssn(match.value)
        elif pii_type == "CREDIT_CARD":
            fake_value = self._fake_credit_card()
        elif pii_type == "NAME":
            fake_value = self._fake_name()
        elif pii_type == "ADDRESS":
            fake_value = self._fake_address()
        elif pii_type == "IP_ADDRESS":
            fake_value = self._fake_ip(match.value)
        else:
            fake_value = self.fake.word()
        
        # Cache the replacement
        self._replacement_cache[cache_key] = fake_value
        
        return fake_value
    
    def _fake_email(self, original: str) -> str:
        """
        Generate fake email address.
        
        Args:
            original: Original email to replace
            
        Returns:
            Fake email address
        """
        if self.preserve_format and '@' in original:
            # Keep the domain if preserve_format is enabled
            domain = original.split('@')[1]
            local = self.fake.user_name()
            return f"{local}@{domain}"
        else:
            return self.fake.email()
    
    def _fake_phone(self, original: str) -> str:
        """
        Generate fake phone number.
        
        Args:
            original: Original phone number
            
        Returns:
            Fake phone number in similar format
        """
        return self.fake.phone_number()
    
    def _fake_ssn(self, original: str) -> str:
        """
        Generate fake SSN.
        
        Args:
            original: Original SSN
            
        Returns:
            Fake SSN in same format
        """
        return self.fake.ssn()
    
    def _fake_credit_card(self) -> str:
        """
        Generate fake credit card number.
        
        Returns:
            Fake credit card number
        """
        return self.fake.credit_card_number()
    
    def _fake_name(self) -> str:
        """
        Generate fake person name.
        
        Returns:
            Fake name
        """
        return self.fake.name()
    
    def _fake_address(self) -> str:
        """
        Generate fake address or location.
        
        Returns:
            Fake location
        """
        # For GPE entities, use city instead of full address
        return self.fake.city()
    
    def _fake_ip(self, original: str) -> str:
        """
        Generate fake IP address.
        
        Args:
            original: Original IP address
            
        Returns:
            Fake IP address (IPv4 or IPv6)
        """
        if ':' in original:
            return self.fake.ipv6()
        else:
            return self.fake.ipv4()
    
    def get_strategy_name(self) -> str:
        """Return strategy name."""
        return "replace"

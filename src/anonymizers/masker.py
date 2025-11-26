"""
Masking anonymizer - partially masks PII while keeping some characters visible.

This strategy maintains some readability while protecting sensitive information.
"""

import re
from src.anonymizers.base_anonymizer import BaseAnonymizer
from src.models import PIIMatch


class Masker(BaseAnonymizer):
    """
    Masking anonymizer that partially masks PII.
    
    Examples:
        - john.doe@example.com -> j***@example.com
        - 555-123-4567 -> 555-***-****
        - 123-45-6789 -> ***-**-6789
        - 4532-1234-5678-9010 -> ****-****-****-9010
    """
    
    def __init__(self, config: dict):
        """
        Initialize masker.
        
        Args:
            config: Configuration dictionary with masking options
        """
        super().__init__(config)
        
        # Get masking character from config
        self.mask_char = self.get_config_option('mask_char', '*')
        
        # Visible character counts for different PII types
        self.email_visible = self.get_config_option('email_visible_chars', 1)
        self.phone_visible = self.get_config_option('phone_visible_chars', 3)
        self.ssn_visible = self.get_config_option('ssn_visible_chars', 4)
        self.credit_card_visible = self.get_config_option('credit_card_visible_chars', 4)
    
    def anonymize(self, match: PIIMatch, context: str = "") -> str:
        """
        Anonymize PII by partial masking.
        
        Args:
            match: PIIMatch object containing the PII to mask
            context: Optional full text context (unused in this strategy)
            
        Returns:
            Partially masked string
        """
        pii_type = match.pii_type
        value = match.value
        
        # Route to appropriate masking method based on PII type
        if pii_type == "EMAIL":
            return self._mask_email(value)
        elif pii_type == "PHONE":
            return self._mask_phone(value)
        elif pii_type == "SSN":
            return self._mask_ssn(value)
        elif pii_type == "CREDIT_CARD":
            return self._mask_credit_card(value)
        elif pii_type == "IP_ADDRESS":
            return self._mask_ip(value)
        else:
            # Generic masking for other types
            return self._mask_generic(value)
    
    def _mask_email(self, email: str) -> str:
        """
        Mask email address.
        
        Args:
            email: Email address to mask
            
        Returns:
            Masked email (e.g., j***@example.com)
        """
        if '@' not in email:
            return self._mask_generic(email)
        
        local, domain = email.split('@', 1)
        
        # Show first N characters of local part
        visible = local[:self.email_visible]
        masked = self.mask_char * max(1, len(local) - self.email_visible)
        
        return f"{visible}{masked}@{domain}"
    
    def _mask_phone(self, phone: str) -> str:
        """
        Mask phone number.
        
        Args:
            phone: Phone number to mask
            
        Returns:
            Masked phone (e.g., 555-***-****)
        """
        # Extract digits
        digits = re.sub(r'\D', '', phone)
        
        if len(digits) < self.phone_visible:
            return self.mask_char * len(phone)
        
        # Keep area code visible (first 3 digits)
        visible = digits[:self.phone_visible]
        
        # Reconstruct with masking
        if '(' in phone:
            # Format: (555) 123-4567 -> (555) ***-****
            return f"({visible}) {self.mask_char * 3}-{self.mask_char * 4}"
        elif '-' in phone or '.' in phone:
            # Format: 555-123-4567 -> 555-***-****
            sep = '-' if '-' in phone else '.'
            return f"{visible}{sep}{self.mask_char * 3}{sep}{self.mask_char * 4}"
        else:
            # Format: 5551234567 -> 555*******
            return visible + (self.mask_char * (len(digits) - self.phone_visible))
    
    def _mask_ssn(self, ssn: str) -> str:
        """
        Mask Social Security Number.
        
        Args:
            ssn: SSN to mask
            
        Returns:
            Masked SSN (e.g., ***-**-6789)
        """
        # Extract digits
        digits = re.sub(r'\D', '', ssn)
        
        if len(digits) != 9:
            return self._mask_generic(ssn)
        
        # Show last 4 digits
        visible = digits[-self.ssn_visible:]
        
        # Reconstruct with masking
        if '-' in ssn:
            return f"{self.mask_char * 3}-{self.mask_char * 2}-{visible}"
        elif ' ' in ssn:
            return f"{self.mask_char * 3} {self.mask_char * 2} {visible}"
        else:
            return (self.mask_char * (9 - self.ssn_visible)) + visible
    
    def _mask_credit_card(self, card: str) -> str:
        """
        Mask credit card number.
        
        Args:
            card: Credit card number to mask
            
        Returns:
            Masked card number (e.g., ****-****-****-1234)
        """
        # Extract digits
        digits = re.sub(r'\D', '', card)
        
        if len(digits) < 13:
            return self._mask_generic(card)
        
        # Show last 4 digits
        visible = digits[-self.credit_card_visible:]
        masked_length = len(digits) - self.credit_card_visible
        
        # Reconstruct with masking
        if '-' in card or ' ' in card:
            sep = '-' if '-' in card else ' '
            # Assume 4-4-4-4 format
            return f"{self.mask_char * 4}{sep}{self.mask_char * 4}{sep}{self.mask_char * 4}{sep}{visible}"
        else:
            return (self.mask_char * masked_length) + visible
    
    def _mask_ip(self, ip: str) -> str:
        """
        Mask IP address.
        
        Args:
            ip: IP address to mask
            
        Returns:
            Masked IP (e.g., 192.168.***.*** or ***.***.1.100)
        """
        if ':' in ip:
            # IPv6 - mask middle portions
            parts = ip.split(':')
            if len(parts) > 4:
                masked_parts = parts[:2] + [self.mask_char * 4] * (len(parts) - 4) + parts[-2:]
                return ':'.join(masked_parts)
        else:
            # IPv4 - mask last two octets
            parts = ip.split('.')
            if len(parts) == 4:
                return f"{parts[0]}.{parts[1]}.{self.mask_char * 3}.{self.mask_char * 3}"
        
        return self._mask_generic(ip)
    
    def _mask_generic(self, value: str) -> str:
        """
        Generic masking for unknown types.
        
        Args:
            value: Value to mask
            
        Returns:
            Mostly masked string (show first character)
        """
        if len(value) <= 1:
            return self.mask_char
        
        return value[0] + (self.mask_char * (len(value) - 1))
    
    def get_strategy_name(self) -> str:
        """Return strategy name."""
        return "mask"

"""Brands commonly impersonated in phishing, with the registrable domains they really own.

Shared by several analyzers (URLs now, display-name spoofing in headers later).
Brand keys must be whole words: they are matched against domain tokens, not substrings.
"""

BRANDS: dict[str, set[str]] = {
    "paypal": {"paypal.com", "paypal.me", "paypalobjects.com"},
    "microsoft": {"microsoft.com", "microsoftonline.com", "live.com", "office.com", "outlook.com"},
    "office365": {"microsoft.com", "microsoftonline.com", "office.com", "office365.com"},
    "outlook": {"outlook.com", "microsoft.com", "live.com"},
    "google": {"google.com", "gmail.com", "youtube.com", "googleusercontent.com"},
    "apple": {"apple.com", "icloud.com"},
    "icloud": {"icloud.com", "apple.com"},
    "amazon": {"amazon.com", "amazon.fr", "amazon.de", "amazon.co.uk", "amazonaws.com"},
    "netflix": {"netflix.com"},
    "facebook": {"facebook.com", "fb.com", "meta.com"},
    "instagram": {"instagram.com"},
    "linkedin": {"linkedin.com"},
    "chase": {"chase.com"},
    "dhl":{"dhl.com", "dhl.fr", "dhl.de"},
    "docusign": {"docusign.com", "docusign.net"},
}

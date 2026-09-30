"""Brands commonly impersonated in phishing, with the registrable domains they really own.
Also the free webmail providers anyone can create an address on.

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

# Anyone can create an address here in 2 minutes. A brand never sends its official mail from them,
# even when the brand owns the provider (Microsoft doesn't email you from a random @outlook.com).
FREE_WEBMAIL: set[str] = {
    "gmail.com", "googlemail.com", "outlook.com", "outlook.fr", "hotmail.com", "hotmail.fr",
    "live.com", "live.fr", "msn.com", "yahoo.com", "yahoo.fr", "aol.com", "icloud.com", "me.com",
    "proton.me", "protonmail.com", "gmx.com", "gmx.fr", "mail.com", "yandex.com", "yandex.ru",
    "mail.ru", "zoho.com", "laposte.net", "orange.fr", "free.fr", "sfr.fr",
}

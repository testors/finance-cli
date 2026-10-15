"""User-entered amount separators, before institution-specific validation."""


def ungroup_amount(value):
    """Remove display commas without coercing signs, decimals, or other input."""
    return value.replace(',', '') if isinstance(value, str) else value

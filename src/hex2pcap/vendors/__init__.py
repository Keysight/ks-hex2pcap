"""Vendor plugin registry."""

from ..metadata import MetadataPlugin

_REGISTRY: dict = {}


def register_vendor(cls):
    """Decorator to register a vendor plugin class."""
    _REGISTRY[cls.name] = cls
    return cls


def get_vendor(name: str) -> MetadataPlugin:
    """Instantiate a vendor plugin by name."""
    # Import vendor modules to trigger registration
    from . import edav2  # noqa: F401

    if name not in _REGISTRY:
        available = ", ".join(sorted(_REGISTRY.keys()))
        raise ValueError(f"Unknown vendor '{name}'. Available: {available}")
    return _REGISTRY[name]()


def available_vendors() -> list:
    """Return list of registered vendor names."""
    from . import edav2  # noqa: F401
    return sorted(_REGISTRY.keys())

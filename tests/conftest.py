"""Shared deterministic settings for property-based tests."""

from hypothesis import HealthCheck, settings

settings.register_profile(
    "fetech",
    max_examples=50,
    deadline=500,
    derandomize=True,
    database=None,
    suppress_health_check=(HealthCheck.too_slow,),
)
settings.load_profile("fetech")

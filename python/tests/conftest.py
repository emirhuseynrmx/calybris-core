"""pytest configuration for the calybris Python test suite."""

from hypothesis import settings

settings.register_profile("ci", max_examples=50, deadline=5_000)
settings.register_profile("fast", max_examples=20, deadline=2_000)
settings.register_profile("thorough", max_examples=500, deadline=None)
settings.load_profile("ci")

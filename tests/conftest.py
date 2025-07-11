"""
Main conftest.py for all tests.
"""

import sys
from pathlib import Path
import pytest

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

# Import all fixtures from the fixtures module
from tests.fixtures.conftest import *

def pytest_configure(config):
    """Configure pytest."""
    config.addinivalue_line(
        "markers", "slow: marks tests as slow (deselect with '-m \"not slow\"')"
    )
    config.addinivalue_line(
        "markers", "integration: marks tests as integration tests"
    )
    config.addinivalue_line(
        "markers", "compliance: marks tests as FDA compliance tests"
    )
    config.addinivalue_line(
        "markers", "performance: marks tests as performance tests"
    )


def pytest_collection_modifyitems(config, items):
    """Modify test collection to add markers."""
    for item in items:
        # Mark performance tests
        if "test_performance" in str(item.fspath):
            item.add_marker(pytest.mark.performance)
        
        # Mark compliance tests
        if "test_fda" in str(item.fspath) or "compliance" in str(item.fspath):
            item.add_marker(pytest.mark.compliance)
        
        # Mark integration tests
        if "integration" in str(item.fspath):
            item.add_marker(pytest.mark.integration)
        
        # Mark slow tests
        if any(marker in item.name.lower() for marker in ["large", "performance", "vulnerability"]):
            item.add_marker(pytest.mark.slow)

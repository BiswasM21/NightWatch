"""
NightWatch — AI-Powered Attack Surface Monitoring Framework.

A modular, extensible reconnaissance and security monitoring framework
for security researchers and ethical hackers.

Example:
    from nightwatch import NightWatchEngine
    engine = NightWatchEngine()
    await engine.create_project("myproject", "example.com")
    results = await engine.run_full_scan(pid, ["example.com"])
"""

__version__ = "1.0.0"
__author__ = "Biswas"
__email__ = "BiswasM21@users.noreply.github.com"
__url__ = "https://github.com/BiswasM21/NightWatch"
__license__ = "MIT"

from .core.engine import NightWatchEngine
from .core.config import Config, get_config
from .db.session import Database, get_db

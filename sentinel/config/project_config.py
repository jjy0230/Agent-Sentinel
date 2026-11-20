"""Project Configuration and Ecosystem Presets Manager.

Loads project-scoped rules from `.sentinel.yaml` to tailor gateway behavior
for specific developer ecosystems (Node.js, Python/AI, Rust, Cloud/DevOps).
"""

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional
try:
    import yaml
except ImportError:
    yaml = None

PRESET_CONFIGS: Dict[str, Dict[str, Any]] = {
    "node": {
        "preset": "node",
        "description": "Full-stack Node.js / TypeScript Web Development",
        "allowed_prefixes": [
            "npm ", "npx ", "pnpm ", "yarn ", "node ", "vite ", "vitest ", "eslint "
        ],
        "auto_trash": True,
        "safe_directories": ["node_modules", "dist", "build", ".next", ".turbo"],
    },
    "python": {
        "preset": "python",
        "description": "Python, Data Science & AI Development",
        "allowed_prefixes": [
            "python ", "python3 ", "pip ", "uv ", "poetry ", "pytest ", "ruff ", "mypy ", "black "
        ],
        "auto_trash": True,
        "safe_directories": ["__pycache__", ".pytest_cache", ".venv", "build", "dist"],
    },
    "rust": {
        "preset": "rust",
        "description": "Rust Systems Programming",
        "allowed_prefixes": [
            "cargo ", "rustc ", "rustfmt ", "clippy "
        ],
        "auto_trash": True,
        "safe_directories": ["target"],
    },
    "cloud": {
        "preset": "cloud",
        "description": "Cloud Native, Docker & Infrastructure",
        "allowed_prefixes": [
            "docker ", "kubectl ", "helm ", "terraform ", "aws ", "gcloud "
        ],
        "auto_trash": False,
        "safe_directories": [".terraform"],
    },
}


@dataclass
class ProjectConfig:
    preset: str = "default"
    auto_trash: bool = True
    auto_snapshot: bool = True
    allowed_prefixes: List[str] = field(default_factory=list)
    safe_directories: List[str] = field(default_factory=list)
    config_file_path: Optional[str] = None

    @classmethod
    def load(cls, start_dir: Optional[str] = None) -> "ProjectConfig":
        """Search upwards for .sentinel.yaml config file."""
        current = Path(start_dir or os.getcwd()).resolve()

        for parent in [current] + list(current.parents):
            candidate = parent / ".sentinel.yaml"
            if candidate.exists():
                try:
                    if yaml:
                        data = yaml.safe_load(candidate.read_text(encoding="utf-8")) or {}
                    else:
                        # Fallback basic key-value parser if pyyaml not installed
                        data = {}
                        for line in candidate.read_text(encoding="utf-8").splitlines():
                            if ":" in line and not line.strip().startswith("#"):
                                k, v = line.split(":", 1)
                                data[k.strip()] = v.strip().strip("'\"")
                    preset_name = data.get("preset")
                    base_data = PRESET_CONFIGS.get(preset_name, {})

                    # Merge base preset with project overrides
                    prefixes = list(set(base_data.get("allowed_prefixes", []) + data.get("allowed_prefixes", [])))
                    safe_dirs = list(set(base_data.get("safe_directories", []) + data.get("safe_directories", [])))

                    return cls(
                        preset=preset_name or "custom",
                        auto_trash=data.get("auto_trash", base_data.get("auto_trash", True)),
                        auto_snapshot=data.get("auto_snapshot", True),
                        allowed_prefixes=prefixes,
                        safe_directories=safe_dirs,
                        config_file_path=str(candidate),
                    )
                except Exception:
                    pass

        return cls()

    @staticmethod
    def generate_template(preset: str = "node") -> str:
        """Create a documented .sentinel.yaml configuration string."""
        base = PRESET_CONFIGS.get(preset, PRESET_CONFIGS["node"])
        return (
            f"# Agent-Sentinel Project Configuration\n"
            f"# Preset: {base['description']}\n\n"
            f"preset: {preset}\n"
            f"auto_trash: {str(base['auto_trash']).lower()}      # Automatically divert dangerous rm to .sentinel/trash/\n"
            f"auto_snapshot: true    # Take a 3ms shadow git snapshot before mutations\n\n"
            f"allowed_prefixes:\n"
            + "\n".join(f"  - \"{p}\"" for p in base["allowed_prefixes"])
            + "\n\nsafe_directories:\n"
            + "\n".join(f"  - \"{d}\"" for d in base["safe_directories"])
            + "\n"
        )

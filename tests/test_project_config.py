"""Tests for ProjectConfig and Ecosystem Presets."""

import pytest
from pathlib import Path
from sentinel.config.project_config import ProjectConfig


def test_project_config_template_generation() -> None:
    template = ProjectConfig.generate_template(preset="node")
    assert "preset: node" in template
    assert "npm " in template
    assert "auto_trash: true" in template


def test_project_config_load_custom(tmp_path: Path) -> None:
    config_file = tmp_path / ".sentinel.yaml"
    config_file.write_text(
        "preset: python\nallowed_prefixes:\n  - 'my_tool '\nauto_trash: true\n",
        encoding="utf-8"
    )

    cfg = ProjectConfig.load(start_dir=str(tmp_path))
    assert cfg.preset == "python"
    assert "my_tool " in cfg.allowed_prefixes
    assert "pytest " in cfg.allowed_prefixes  # From base python preset
    assert cfg.auto_trash is True

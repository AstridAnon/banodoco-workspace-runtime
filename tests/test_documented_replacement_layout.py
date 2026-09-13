from pathlib import Path


def test_readme_documents_sibling_support_for_replacement():
    readme = (Path(__file__).parents[1] / "README.md").read_text(encoding="utf-8")
    assert "support custody outside the movable realm root" in readme
    assert "--support-root ./runtime-support" in readme
    assert "default in-root" in readme


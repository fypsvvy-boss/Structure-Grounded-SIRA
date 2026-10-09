"""Which code produced a run: the git commit and whether the tree matched it."""

import subprocess

import pytest

from sira_cti.common import code_version, full_run_blocker


def _git(repo, *args):
    subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True)


@pytest.fixture
def repo(tmp_path):
    _git(tmp_path, "init", "-q")
    _git(tmp_path, "config", "user.email", "test@example.com")
    _git(tmp_path, "config", "user.name", "Test")
    _git(tmp_path, "config", "commit.gpgsign", "false")
    for folder in ("src", "scripts", "configs", "docs"):
        (tmp_path / folder).mkdir()
        (tmp_path / folder / "file.txt").write_text("one\n")
    _git(tmp_path, "add", "-A")
    _git(tmp_path, "commit", "-q", "-m", "first")
    return tmp_path


def test_a_clean_checkout_reports_its_commit_and_is_not_dirty(repo):
    version = code_version(repo)

    assert len(version["code_commit"]) == 40 and version["code_commit"] == version["head"]
    assert version["dirty"] is False and version["dirty_files"] == []
    assert full_run_blocker(version) is None


def test_an_edited_code_file_makes_the_tree_dirty_and_names_the_file(repo):
    (repo / "src" / "file.txt").write_text("two\n")
    version = code_version(repo)

    assert version["dirty"] is True
    assert version["dirty_files"] == ["src/file.txt"]          # the whole name, first letter included


def test_a_new_untracked_code_file_also_counts(repo):
    (repo / "scripts" / "new.py").write_text("print('hi')\n")
    assert code_version(repo)["dirty"] is True


def test_editing_or_committing_documentation_changes_nothing_that_is_checked(repo):
    before = code_version(repo)

    (repo / "docs" / "file.txt").write_text("notes\n")
    assert code_version(repo)["dirty"] is False                 # an uncommitted doc is not a code change

    _git(repo, "commit", "-q", "-am", "docs only")
    after = code_version(repo)
    assert after["head"] != before["head"]                      # the repository moved on...
    assert after["code_commit"] == before["code_commit"]        # ...the code did not


def test_committing_a_code_change_moves_the_code_commit(repo):
    before = code_version(repo)
    (repo / "configs" / "file.txt").write_text("two\n")
    _git(repo, "commit", "-q", "-am", "config change")

    after = code_version(repo)
    assert after["code_commit"] != before["code_commit"] and after["dirty"] is False


def test_outside_a_git_checkout_there_is_no_version_and_nothing_is_blocked(tmp_path):
    assert code_version(tmp_path / "nowhere") is None
    assert full_run_blocker(None) is None


def test_a_full_run_is_refused_on_a_dirty_tree_with_the_files_listed(repo):
    (repo / "src" / "file.txt").write_text("two\n")
    message = full_run_blocker(code_version(repo))

    assert message.startswith("Refusing to start a full-corpus run")
    assert "src/file.txt" in message and "Commit" in message

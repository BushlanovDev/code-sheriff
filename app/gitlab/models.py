"""Typed models for GitLab API responses."""

from typing import TypedDict


class AuthorData(TypedDict, total=False):
    name: str
    username: str


class DiffRefs(TypedDict):
    base_sha: str
    head_sha: str
    start_sha: str


class MergeRequestData(TypedDict, total=False):
    iid: int
    title: str
    description: str | None
    state: str
    sha: str
    source_branch: str
    target_branch: str
    author: AuthorData
    diff_refs: DiffRefs


class MRChange(TypedDict, total=False):
    old_path: str
    new_path: str
    diff: str


class MRChangesData(TypedDict, total=False):
    """Response from GET /merge_requests/:iid/changes."""

    changes: list[MRChange]
    diff_refs: DiffRefs


class NotePosition(TypedDict, total=False):
    old_path: str
    new_path: str
    old_line: int | None
    new_line: int | None


class DiscussionNote(TypedDict, total=False):
    id: int
    body: str
    position: NotePosition | None


class Discussion(TypedDict, total=False):
    notes: list[DiscussionNote]


class DiffPosition(TypedDict):
    """Position payload for creating inline discussions."""

    base_sha: str
    head_sha: str
    start_sha: str
    old_path: str
    new_path: str
    position_type: str
    new_line: int


class ChangeStats(TypedDict):
    files_changed: int
    additions: int
    deletions: int

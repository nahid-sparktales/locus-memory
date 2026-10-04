"""Package search accepts only host-supplied transcript capabilities."""
import json
import os
import threading

from locus_memory.history.transcript_search import (
    TranscriptIndex,
    TranscriptLimits,
    TranscriptSource,
)


def line(role, content):
    return json.dumps({"type": "message", "message": {"role": role, "content": content}}) + "\n"


def test_search_tail_sync_positions_and_host_removal(tmp_path):
    path = tmp_path / "session.jsonl"
    path.write_text(line("tool", "private tool payload") + line("user", "PREFIX: nebula preference"))
    paths = [path]
    index = TranscriptIndex(
        tmp_path / "search.sqlite3",
        TranscriptSource(lambda: paths, lambda: {"session": {"title": "Host title"}},
                         lambda value: value.removeprefix("PREFIX: ")),
        TranscriptLimits(1_000_000, 100_000, 100),
    )
    first = index.search("nebula")["results"][0]
    assert first["message_index"] == 1
    assert first["title"] == "Host title"
    assert "PREFIX" not in first["snippet"]
    assert not index.search("private")["results"]
    with path.open("a") as stream:
        stream.write(line("assistant", "comet checklist"))
    assert index.search("comet")["results"][0]["message_index"] == 2
    paths.clear()
    assert not index.search("nebula")["results"]


def test_torn_transcript_tail_is_deferred_and_host_limits_apply(tmp_path):
    path = tmp_path / "session.jsonl"
    path.write_text(line("user", "first meteor") + line("assistant", "second comet")[:-1])
    index = TranscriptIndex(
        tmp_path / "search.sqlite3",
        TranscriptSource(lambda: [path], dict, lambda text: text),
        TranscriptLimits(1_000_000, 100_000, 2),
    )
    assert index.search("meteor")["results"]
    assert not index.search("comet")["results"]
    with path.open("a") as stream:
        stream.write("\n" + line("user", "third galaxy"))
    assert index.search("comet")["results"]
    assert not index.search("galaxy")["results"]


def test_background_build_cannot_reintroduce_revoked_source(tmp_path):
    path = tmp_path / "session.jsonl"
    path.write_text(line("user", "violet private message"))
    paths = [path]
    release = threading.Event()

    def metadata():
        release.set()
        index._build_thread.join(timeout=5)
        assert not index._build_thread.is_alive()
        return {}

    index = TranscriptIndex(
        tmp_path / "search.sqlite3",
        TranscriptSource(lambda: list(paths), metadata, str),
        TranscriptLimits(1_000_000, 100_000, 100), background_build_bytes=0,
    )
    original = index._index_many

    def delayed(stale):
        if release.wait(timeout=5):
            original(stale)

    index._index_many = delayed
    try:
        assert index.sync()["pending"] == 1
        paths.clear()
        assert not index.search("violet")["results"]
        with index._connect() as connection:
            assert connection.execute("SELECT COUNT(*) FROM messages_fts").fetchone()[0] == 0
    finally:
        release.set()
        if index._build_thread:
            index._build_thread.join(timeout=5)


def test_grants_revoked_during_metadata_lookup_do_not_return_cached_hits(tmp_path):
    path = tmp_path / "session.jsonl"
    path.write_text(line("user", "violet private message"))
    paths = [path]

    def metadata():
        paths.clear()
        return {}

    index = TranscriptIndex(
        tmp_path / "search.sqlite3",
        TranscriptSource(lambda: list(paths), metadata, str),
        TranscriptLimits(1_000_000, 100_000, 100),
    )
    assert not index.search("violet")["results"]


def test_same_size_transcript_rewrite_replaces_cached_text(tmp_path):
    path = tmp_path / "session.jsonl"
    before, after = line("user", "violet question"), line("user", "purple question")
    assert len(before) == len(after)
    path.write_text(before)
    index = TranscriptIndex(
        tmp_path / "search.sqlite3",
        TranscriptSource(lambda: [path], dict, str),
        TranscriptLimits(1_000_000, 100_000, 100),
    )
    assert index.search("violet")["results"]
    stat = path.stat()
    path.write_text(after)
    os.utime(path, (stat.st_atime, stat.st_mtime + 2))
    assert index.search("purple")["results"]
    assert not index.search("violet")["results"]

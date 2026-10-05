import shutil

import pytest

from locus_memory.errors import IntegrityError, ReconciliationRequired
from locus_memory.host import HostCapabilities
from locus_memory.models import ForgetTarget, MemoryKind, RememberRequest, Scope
from locus_memory.storage.ledger import MemoryLedgerMirror


def test_mirror_rejects_backwards_and_equal_generation_fork():
    mirror = MemoryLedgerMirror()
    mirror.write("p", 2, "a")
    for checkpoint in [(1, "a"), (2, "b")]:
        with pytest.raises(IntegrityError):
            mirror.write("p", *checkpoint)
    assert mirror.read("p") == (2, "a")


@pytest.mark.parametrize("longer", [False, True])
def test_equal_or_longer_divergent_chain_is_detected(make_engine, root, user_access, tmp_path, clock, longer):
    mirror = MemoryLedgerMirror()
    engine = make_engine(host=HostCapabilities(clock=clock, ledger_mirror=mirror))
    record = engine.remember(user_access, RememberRequest(scope=Scope.of(project="proj-a"), content="original", kind=MemoryKind.FACT)).record
    engine.close()
    backup = tmp_path / "before"
    shutil.copytree(root, backup)
    engine = make_engine(host=HostCapabilities(clock=clock, ledger_mirror=mirror))
    engine.forget(user_access, ForgetTarget("memory", record.id))
    engine.close()
    baseline = mirror.read(user_access.partition.partition_id)
    shutil.rmtree(root)
    shutil.copytree(backup, root)
    divergent = make_engine(host=HostCapabilities(clock=clock))
    other = divergent.remember(user_access, RememberRequest(scope=Scope.of(project="proj-a"), content="alternate", kind=MemoryKind.FACT)).record
    divergent.forget(user_access, ForgetTarget("memory", other.id))
    if longer:
        divergent.forget(user_access, ForgetTarget("memory", record.id))
    divergent.close()
    engine = make_engine(host=HostCapabilities(clock=clock, ledger_mirror=mirror))
    with pytest.raises(ReconciliationRequired):
        engine.get(user_access, record.id)
    report = engine.reconcile(user_access, acknowledge_mirror_gap=True)
    assert report["deletion_generation"] > baseline[0]
    assert report["deletion_generation"] > (2 if longer else 1)
    engine.close()
    reopened = make_engine(host=HostCapabilities(clock=clock, ledger_mirror=mirror))
    assert reopened.reconcile(user_access)["reapplied"] == 0

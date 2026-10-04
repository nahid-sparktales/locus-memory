"""Authorization checks applied before any content is read, ranked, or returned."""
from __future__ import annotations

from .errors import AccessDenied, NotFound
from .host import HostCapabilities
from .models import AccessContext, Actor, MemoryRecord, Operation, Scope, ScopeGrants


def require(access: AccessContext, operation: Operation) -> None:
    if operation not in access.operations:
        raise AccessDenied(f"operation {operation.value} is not permitted for this caller")


def require_scope(access: AccessContext, scope: Scope) -> None:
    if not access.grants.allows(scope):
        raise AccessDenied("the requested scope is not granted to this caller")


def require_reviewer(access: AccessContext, host: HostCapabilities) -> None:
    """Approval/rejection is human review attested by the host - never a model decision."""
    require(access, Operation.APPROVE)
    if access.actor not in host.approval_actors:
        raise AccessDenied("only a host-attested reviewer can approve or reject memory")


def require_author(access: AccessContext) -> None:
    """Explicit remember/correct are user (or host-on-behalf-of-user) actions."""
    require(access, Operation.WRITE)
    if access.actor not in (Actor.USER, Actor.HOST):
        raise AccessDenied("agents and providers must propose candidates instead of writing memory")


def visible(access: AccessContext, record: MemoryRecord) -> bool:
    return access.grants.allows(record.scope)


def require_visible(access: AccessContext, record: MemoryRecord | None) -> MemoryRecord:
    # Missing and unauthorized are indistinguishable to the caller.
    if record is None or not visible(access, record):
        raise NotFound("memory not found")
    return record


def narrow(grants: ScopeGrants, scope_filter: Scope | None) -> ScopeGrants:
    """Restrict grants to a requested filter. A filter can only narrow, never widen."""
    if scope_filter is None:
        return grants
    values = scope_filter.as_dict()
    kwargs = {}
    for dim, name in ScopeGrants._DIM_FIELDS.items():
        current = grants.values_for(dim)
        if dim in values:
            if values[dim] not in current:
                raise AccessDenied("the requested scope filter is not granted to this caller")
            kwargs[name] = frozenset({values[dim]})
        else:
            kwargs[name] = current
    return ScopeGrants(**kwargs)

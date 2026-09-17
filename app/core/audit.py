"""Structured audit lines for every read and write of patient data.

Healthcare access is meant to be answerable after the fact: who looked at
whose records, from which clinic, and when. These lines are JSON rather than
prose so they can be searched and counted without parsing English.

Deliberately absent: names, emails, reasons for visit, notes. An audit trail
that copies the sensitive data into the log has doubled the number of places
that data lives, and log aggregators are rarely as well guarded as databases.
Ids only — the records themselves are one join away for anyone entitled.
"""

import json
import logging
import uuid
from datetime import UTC, datetime
from typing import Any

logger = logging.getLogger("audit")


def record(
    *,
    action: str,
    tenant_id: uuid.UUID,
    user_id: uuid.UUID,
    request_id: str,
    resource_id: uuid.UUID | None = None,
    outcome: str = "ok",
    **extra: Any,
) -> None:
    line = {
        "at": datetime.now(UTC).isoformat(),
        "action": action,
        "tenant_id": str(tenant_id),
        "user_id": str(user_id),
        "request_id": request_id,
        "outcome": outcome,
    }
    if resource_id is not None:
        line["resource_id"] = str(resource_id)
    line.update({k: str(v) for k, v in extra.items()})
    logger.info(json.dumps(line, separators=(",", ":")))

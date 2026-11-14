"""Registration of isolated read-only AVM2 tools."""
import json
from typing import Annotated, Optional

from pydantic import Field
from .inspection import inspect_avm2, InspectionError

Limit = Annotated[int, Field(ge=1, le=200)]
Budget = Annotated[int, Field(ge=4096, le=131072)]
Index = Annotated[int, Field(ge=0)]
Deadline = Annotated[int, Field(ge=1, le=300)]


def _query(operation, **kwargs):
    try:
        return inspect_avm2(operation, **kwargs)
    except (InspectionError, OSError, ValueError, json.JSONDecodeError) as exc:
        return {"success": False, "error": str(exc), "results": []}


def register_inspection_tools(mcp):
    hints = {"readOnlyHint": True, "destructiveHint": False,
             "idempotentHint": True, "openWorldHint": False}

    @mcp.tool(annotations=hints)
    def list_avm2_classes(
        swf_path: str, abc_index: Optional[Index] = None,
        offset: Index = 0, limit: Limit = 50, max_bytes: Budget = 65_536,
        expected_sha256: Optional[str] = None, timeout: Deadline = 60,
    ) -> dict:
        """Read AVM2 class identities, superclasses, interfaces and initializer IDs without export.

        Instance and static traits include qualified names, kinds and declared_slot_id.
        A zero slot ID requests automatic assignment. Null indicates no slot ID field.
        Requires Java 17+ JDK, FFDec 26.4.0 JAR, FWS/CWS input <=64 MiB.
        For pagination pass next_offset as offset and sha256 as expected_sha256;
        keep every other query parameter unchanged. max_bytes bounds JSON results.
        """
        return _query("classes", swf_path=swf_path, abc_index=abc_index,
            offset=offset, limit=limit, max_bytes=max_bytes,
            expected_sha256=expected_sha256, timeout=timeout)

    @mcp.tool(annotations=hints)
    def inspect_avm2_method(
        swf_path: str, abc_index: Index, method_id: Index,
        offset: Index = 0, limit: Limit = 50, max_bytes: Budget = 65_536,
        expected_sha256: Optional[str] = None, timeout: Deadline = 60,
    ) -> dict:
        """Read a method signature, owners, exception table and decoded bytecode without export.

        Results are paginated rows: first method metadata, then instructions.
        offset counts rows, not bytecode bytes. Continue with next_offset and
        expected_sha256, preserving the other parameters. Initial support:
        Java 17+ JDK, FFDec 26.4.0 JAR, FWS/CWS <=64 MiB.
        Slot names, receiver types and execution reachability are not inferred.
        """
        return _query("method", swf_path=swf_path, abc_index=abc_index,
            method_id=method_id, offset=offset, limit=limit, max_bytes=max_bytes,
            expected_sha256=expected_sha256, timeout=timeout)

    @mcp.tool(annotations=hints)
    def find_avm2_property_accesses(
        swf_path: str, property_name: str = "", access: str = "write",
        abc_index: Optional[Index] = None, offset: Index = 0,
        limit: Limit = 50, max_bytes: Budget = 65_536,
        expected_sha256: Optional[str] = None, timeout: Deadline = 60,
    ) -> dict:
        """Find property reads/writes with containing methods, lexical contexts and bytecode offsets.

        Read-only, no export. property_name is an exact simple-name filter;
        empty includes runtime-computed names and unresolved slot accesses.
        access: read, write or all. Includes get/setproperty, get/setsuper,
        initproperty, get/setslot and get/setglobalslot, not calls or deletes.
        Writes to proven activation, catch or class receivers match by name.
        slot_resolution identifies activation_trait, catch_scope, instance_trait
        or static_trait. Class matches include the receiver class name.
        Named catch writes in detached empty-range handlers can report
        reachability="unreachable" when no method-entry path reaches the write.
        Namespaces are preserved as multinames.
        Continue using next_offset and expected_sha256 with unchanged filters.
        Requires Java 17+ JDK, FFDec 26.4.0 JAR, FWS/CWS <=64 MiB.
        """
        return _query("accesses", swf_path=swf_path, property_name=property_name,
            access=access, abc_index=abc_index, offset=offset, limit=limit,
            max_bytes=max_bytes, expected_sha256=expected_sha256, timeout=timeout)

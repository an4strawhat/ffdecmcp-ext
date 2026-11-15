"""Registration of isolated read-only SWF and AVM2 tools."""
import json
from typing import Annotated, Literal, Optional

from pydantic import Field
from .inspection import compare_avm2 as compare_swf_methods, inspect_avm2, InspectionError

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
    def compare_avm2(
        original_swf_path: str, patched_swf_path: str,
        include_unchanged: bool = False, offset: Index = 0, limit: Limit = 50,
        instruction_offset: Index = 0,
        max_bytes: Budget = 65_536, expected_original_sha256: Optional[str] = None,
        expected_patched_sha256: Optional[str] = None, timeout: Deadline = 60,
    ) -> dict:
        """Compare AVM2 method bodies in two SWFs without exporting scripts.

        Matches unique named trait or initializer owners and signatures across
        reordered ABC blocks and method IDs. Anonymous bodies can match by
        signature under a matched enclosing method through a unique newfunction
        site. Each matched closure location includes enclosing_method_id.
        Anonymous bodies without a unique context are unmatched, duplicate
        identities are ambiguous, and unresolved operands produce indeterminate
        comparisons. Use each location's abc_index and method_id with
        inspect_avm2_method. A changed named signature can appear as a removal
        and addition. The summary includes unchanged pairs
        even when their rows are hidden. Continue with next_offset and both
        returned SHA-256 values, keeping other options fixed.
        Changed rows show original/patched instructions with offsets, opcodes,
        operands and bytes. To continue a row's instruction changes, select
        that method row using offset and limit=1, then pass its
        next_instruction_offset as instruction_offset with both SHA-256 values.
        Requires Java 17+ JDK, FFDec 26.4.0 or 26.5.0 JAR, FWS/CWS/ZWS <=64 MiB per input.
        """
        try:
            return compare_swf_methods(original_swf_path, patched_swf_path,
                include_unchanged=include_unchanged, offset=offset, limit=limit,
                max_bytes=max_bytes, expected_original_sha256=expected_original_sha256,
                expected_patched_sha256=expected_patched_sha256, timeout=timeout,
                instruction_offset=instruction_offset)
        except (OSError, ValueError) as exc:
            return {"success": False, "error": str(exc), "results": []}

    @mcp.tool(annotations=hints)
    def inspect_swf_linkage(
        swf_path: str,
        kind: Literal["all", "symbol_class", "export_asset", "placement"] = "all",
        character_id: Optional[Annotated[int, Field(ge=0, le=65535)]] = None,
        timeline: Literal["all", "root", "nested"] = "all",
        offset: Index = 0, limit: Limit = 50, max_bytes: Budget = 65_536,
        expected_sha256: Optional[str] = None, timeout: Deadline = 60,
    ) -> dict:
        """Read SymbolClass, ExportAssets and PlaceObject tags without exporting files.

        Filter by row kind, explicit character ID, or timeline. Character ID
        0 includes the document class. timeline_path lists enclosing sprite IDs
        from outermost to innermost (empty for root). Frame numbers start at 1
        and tag_index starts at 0 within its timeline. Placements are tag events.
        A null character_id means the tag omits an ID, as in class-only or
        move-only records. class_name and instance_name come from the tag.
        Continue with next_offset and sha256 as expected_sha256, with the same
        filters. Requires Java 17+ JDK, FFDec 26.4.0 or 26.5.0 JAR, FWS/CWS/ZWS <=64 MiB.
        """
        return _query("linkage", swf_path=swf_path, linkage_kind=kind,
            character_id=character_id, timeline=timeline, offset=offset,
            limit=limit, max_bytes=max_bytes, expected_sha256=expected_sha256,
            timeout=timeout)

    @mcp.tool(annotations=hints)
    def list_avm2_classes(
        swf_path: str, abc_index: Optional[Index] = None,
        offset: Index = 0, limit: Limit = 50, max_bytes: Budget = 65_536,
        expected_sha256: Optional[str] = None, timeout: Deadline = 60,
    ) -> dict:
        """Read AVM2 class identities, superclasses, interfaces and initializer IDs without export.

        Instance and static traits include qualified names, kinds and declared_slot_id.
        A zero slot ID requests automatic assignment. Null indicates no slot ID field.
        Requires Java 17+ JDK, FFDec 26.4.0 or 26.5.0 JAR, FWS/CWS/ZWS input <=64 MiB.
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
        Java 17+ JDK, FFDec 26.4.0 or 26.5.0 JAR, FWS/CWS/ZWS <=64 MiB.
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
        Requires Java 17+ JDK, FFDec 26.4.0 or 26.5.0 JAR, FWS/CWS/ZWS <=64 MiB.
        """
        return _query("accesses", swf_path=swf_path, property_name=property_name,
            access=access, abc_index=abc_index, offset=offset, limit=limit,
            max_bytes=max_bytes, expected_sha256=expected_sha256, timeout=timeout)

"""FastMCP server with FFDec tools."""

import logging
import sys
from typing import Any, Optional

from fastmcp import FastMCP

from .ffdec import FFDecError, FFDecWrapper

# Configure logging to stderr (critical for STDIO transport)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    stream=sys.stderr,
)
logger = logging.getLogger(__name__)

# Initialize FastMCP server
mcp = FastMCP("ffdecmcp")

# Independent library-backed layer; existing CLI tools retain their behavior.
from .inspection_tools import register_inspection_tools
register_inspection_tools(mcp)

# Lazy-initialized FFDec wrapper (config must be ready before first tool call)
_ffdec: Optional[FFDecWrapper] = None


def get_ffdec() -> FFDecWrapper:
    """Get or create FFDec wrapper instance."""
    global _ffdec
    if _ffdec is None:
        _ffdec = FFDecWrapper()
    return _ffdec


@mcp.tool()
def decompile_swf(
    swf_path: str,
    output_dir: str,
    timeout: Optional[int] = None,
) -> dict[str, Any]:
    """
    Decompile all ActionScript code from a SWF file.

    This tool extracts and decompiles all ActionScript (AS2/AS3) code from a Flash SWF file,
    organizing the output into a directory structure that mirrors the package hierarchy.

    Args:
        swf_path: Absolute path to the SWF file to decompile
        output_dir: Directory where decompiled scripts will be saved
        timeout: Optional timeout in seconds (default: 60)

    Returns:
        Dictionary with:
        - success: Whether decompilation succeeded
        - swf_path: Input SWF file path
        - output_dir: Output directory path
        - script_count: Number of ActionScript files extracted
        - message: Success message

    Example:
        >>> decompile_swf("/path/to/game.swf", "/path/to/output")
        {
            "success": true,
            "swf_path": "/path/to/game.swf",
            "output_dir": "/path/to/output",
            "script_count": 42,
            "message": "Successfully decompiled 42 ActionScript files"
        }
    """
    try:
        logger.info(f"Decompiling SWF: {swf_path} -> {output_dir}")
        result = get_ffdec().decompile_swf(swf_path, output_dir, timeout)
        logger.info(f"Decompilation complete: {result['script_count']} files")
        return result
    except FFDecError as e:
        logger.error(f"Decompilation failed: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": f"Decompilation failed: {e}",
        }
    except Exception as e:
        logger.error(f"Unexpected error during decompilation: {e}", exc_info=True)
        return {
            "success": False,
            "error": str(e),
            "message": f"Unexpected error: {e}",
        }


@mcp.tool()
def extract_actionscript(
    swf_path: str,
    class_names: list[str],
    output_dir: str,
    timeout: Optional[int] = None,
) -> dict[str, Any]:
    """
    Extract specific ActionScript classes by name from a SWF file.

    This tool selectively extracts only the specified ActionScript classes (AS3 only),
    which is faster than full decompilation when you only need specific classes.

    Args:
        swf_path: Absolute path to the SWF file
        class_names: List of fully-qualified class names to extract (e.g., ['com.example.Main', 'com.example.Utils'])
        output_dir: Directory where extracted classes will be saved
        timeout: Optional timeout in seconds (default: 60)

    Returns:
        Dictionary with:
        - success: Whether extraction succeeded
        - swf_path: Input SWF file path
        - output_dir: Output directory path
        - requested_classes: List of requested class names
        - extracted_files: Number of files extracted
        - message: Success message

    Example:
        >>> extract_actionscript("/path/to/game.swf", ["com.game.Main", "com.game.Player"], "/path/to/output")
        {
            "success": true,
            "swf_path": "/path/to/game.swf",
            "output_dir": "/path/to/output",
            "requested_classes": ["com.game.Main", "com.game.Player"],
            "extracted_files": 2,
            "message": "Successfully extracted 2 ActionScript files"
        }
    """
    try:
        logger.info(
            f"Extracting ActionScript classes from {swf_path}: {class_names}"
        )
        result = get_ffdec().extract_actionscript(swf_path, class_names, output_dir, timeout)
        logger.info(f"Extraction complete: {result['extracted_files']} files")
        return result
    except FFDecError as e:
        logger.error(f"ActionScript extraction failed: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": f"ActionScript extraction failed: {e}",
        }
    except Exception as e:
        logger.error(
            f"Unexpected error during ActionScript extraction: {e}", exc_info=True
        )
        return {
            "success": False,
            "error": str(e),
            "message": f"Unexpected error: {e}",
        }


@mcp.tool()
def list_symbols(swf_path: str) -> dict[str, Any]:
    """
    List all ActionScript classes and symbols in a SWF file.

    This tool provides an overview of the ActionScript structure without decompiling,
    showing packages, classes, and the total symbol count. Useful for exploring a SWF
    before full decompilation.

    Args:
        swf_path: Absolute path to the SWF file

    Returns:
        Dictionary with:
        - success: Whether listing succeeded
        - type: ActionScript type (AS2, AS3, or Unknown)
        - packages: Dictionary mapping package names to class lists
        - classes: Complete list of fully-qualified class names
        - total_symbols: Total number of classes found
        - message: Summary message

    Example:
        >>> list_symbols("/path/to/game.swf")
        {
            "success": true,
            "type": "AS3",
            "packages": {
                "com.game": ["Main", "Player", "Enemy"],
                "com.game.utils": ["Vector2D", "Math"]
            },
            "classes": ["com.game.Main", "com.game.Player", ...],
            "total_symbols": 5,
            "message": "Found 5 AS3 classes in 2 packages"
        }
    """
    try:
        logger.info(f"Listing symbols in SWF: {swf_path}")
        result = get_ffdec().list_symbols(swf_path)
        logger.info(f"Symbol listing complete: {result['total_symbols']} symbols")
        return result
    except FFDecError as e:
        logger.error(f"Symbol listing failed: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": f"Symbol listing failed: {e}",
        }
    except Exception as e:
        logger.error(f"Unexpected error during symbol listing: {e}", exc_info=True)
        return {
            "success": False,
            "error": str(e),
            "message": f"Unexpected error: {e}",
        }


@mcp.tool()
def extract_assets(
    swf_path: str,
    output_dir: str,
    asset_types: Optional[list[str]] = None,
    formats: Optional[list[str]] = None,
    select: Optional[str] = None,
    select_ids: Optional[str] = None,
    zoom: Optional[int] = None,
    ignore_background: bool = False,
    onerror: Optional[str] = None,
    onerror_retries: int = 3,
    export_timeout: Optional[int] = None,
    timeout: Optional[int] = None,
) -> dict[str, Any]:
    """
    Extract images, sounds, fonts, and other assets from a SWF file.

    This tool extracts assets from a Flash SWF file, including images, sounds,
    fonts, shapes, movie clips, binary data, plus texts, rendered frames/sprites,
    buttons, morphshapes, symbol-class mappings, and FLA/XFL project export.

    Args:
        swf_path: Absolute path to the SWF file
        output_dir: Directory where extracted assets will be saved
        asset_types: Optional list of asset types to extract. Valid types:
            'image', 'sound', 'font', 'font4', 'shape', 'morphshape', 'movie',
            'frame', 'sprite', 'button', 'binaryData', 'symbolClass', 'text',
            'all', 'fla', 'xfl' (default: ['all'])
        formats: Optional list of -format values, e.g. ['script:pcode',
            'shape:svg', 'frame:png', 'image:webp'] to control output formats
        select: Optional -select frame ranges, e.g. '1-5', '2,3', 'all:12-29'
        select_ids: Optional -selectid character id ranges, e.g. '1-5', '2,3'
        zoom: Optional zoom level applied during export
        ignore_background: If True, ignore SWF background color (transparent frames)
        onerror: Optional error handling mode: 'abort', 'retry', 'ignore'
        onerror_retries: Retry count when onerror is 'retry' (default: 3)
        export_timeout: Optional total export timeout in seconds
        timeout: Optional timeout in seconds (default: 60)

    Returns:
        Dictionary with:
        - success: Whether extraction succeeded
        - swf_path: Input SWF file path
        - output_dir: Output directory path
        - asset_types: List of asset types extracted
        - extracted_count: Number of assets extracted
        - message: Success message

    Example:
        >>> extract_assets("/path/to/game.swf", "/path/to/output", asset_types=["image", "sound"])
        {
            "success": true,
            "swf_path": "/path/to/game.swf",
            "output_dir": "/path/to/output",
            "asset_types": ["image", "sound"],
            "extracted_count": 127,
            "message": "Successfully extracted 127 assets"
        }
    """
    try:
        logger.info(
            f"Extracting assets from {swf_path}: types={asset_types or ['all']}"
        )
        result = get_ffdec().extract_assets(
            swf_path,
            output_dir,
            asset_types,
            formats,
            select,
            select_ids,
            zoom,
            ignore_background,
            onerror,
            onerror_retries,
            export_timeout,
            timeout,
        )
        logger.info(f"Asset extraction complete: {result['extracted_count']} files")
        return result
    except FFDecError as e:
        logger.error(f"Asset extraction failed: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": f"Asset extraction failed: {e}",
        }
    except Exception as e:
        logger.error(f"Unexpected error during asset extraction: {e}", exc_info=True)
        return {
            "success": False,
            "error": str(e),
            "message": f"Unexpected error: {e}",
        }


@mcp.tool()
def get_swf_metadata(swf_path: str) -> dict[str, Any]:
    """
    Extract metadata from a SWF file's header.

    This tool reads the SWF file header to extract basic metadata like dimensions,
    frame rate, frame count, compression type, and Flash version. This is fast and
    doesn't require decompilation.

    Args:
        swf_path: Absolute path to the SWF file

    Returns:
        Dictionary with metadata including:
        - success: Whether extraction succeeded
        - swf_path: Input SWF file path
        - version: Flash version number
        - width: Stage width in pixels
        - height: Stage height in pixels
        - frame_rate: Frames per second
        - frame_count: Total number of frames
        - compression: Compression type (e.g., 'zlib', 'lzma', 'none')
        - Additional header fields as available

    Example:
        >>> get_swf_metadata("/path/to/game.swf")
        {
            "success": true,
            "swf_path": "/path/to/game.swf",
            "version": 10,
            "width": 800,
            "height": 600,
            "frame_rate": 30,
            "frame_count": 1,
            "compression": "zlib"
        }
    """
    try:
        logger.info(f"Extracting metadata from SWF: {swf_path}")
        result = get_ffdec().get_swf_metadata(swf_path)
        logger.info(f"Metadata extraction complete")
        return result
    except FFDecError as e:
        logger.error(f"Metadata extraction failed: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": f"Metadata extraction failed: {e}",
        }
    except Exception as e:
        logger.error(
            f"Unexpected error during metadata extraction: {e}", exc_info=True
        )
        return {
            "success": False,
            "error": str(e),
            "message": f"Unexpected error: {e}",
        }


@mcp.tool()
def deobfuscate(
    swf_path: str,
    output_path: str,
    level: str = "max",
    timeout: Optional[int] = None,
) -> dict[str, Any]:
    """
    Deobfuscate a SWF file by removing obfuscation techniques.

    This tool runs FFDec's deobfuscation algorithms to remove common obfuscation
    techniques like dead code, traps, and other anti-decompilation tricks. The
    output is a cleaner SWF file that's easier to decompile and analyze.

    Args:
        swf_path: Absolute path to the obfuscated SWF file
        output_path: Path where the deobfuscated SWF will be saved
        level: Deobfuscation level - 'traps' (remove traps only), 'deadcode' (remove dead code), 'max' (full deobfuscation, default)
        timeout: Optional timeout in seconds (default: 60)

    Returns:
        Dictionary with:
        - success: Whether deobfuscation succeeded
        - input_path: Input SWF file path
        - output_path: Output SWF file path
        - level: Deobfuscation level used
        - message: Success message

    Example:
        >>> deobfuscate("/path/to/obfuscated.swf", "/path/to/clean.swf", level="max")
        {
            "success": true,
            "input_path": "/path/to/obfuscated.swf",
            "output_path": "/path/to/clean.swf",
            "level": "max",
            "message": "Successfully deobfuscated SWF at level 'max'"
        }
    """
    try:
        logger.info(
            f"Deobfuscating SWF: {swf_path} -> {output_path} (level={level})"
        )
        result = get_ffdec().deobfuscate(swf_path, output_path, level, timeout)
        logger.info(f"Deobfuscation complete")
        return result
    except FFDecError as e:
        logger.error(f"Deobfuscation failed: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": f"Deobfuscation failed: {e}",
        }
    except Exception as e:
        logger.error(f"Unexpected error during deobfuscation: {e}", exc_info=True)
        return {
            "success": False,
            "error": str(e),
            "message": f"Unexpected error: {e}",
        }


# ----------------------------------------------------------------------
# Extended tools: inspection
# ----------------------------------------------------------------------


@mcp.tool()
def dump_swf(
    swf_path: str,
    timeout: Optional[int] = None,
    outfile: Optional[str] = None,
    max_chars: int = 250_000,
) -> dict[str, Any]:
    """
    Dump the list of all SWF tags to console output.

    This tool lists every tag in the SWF file (tag code, name, index), which is
    useful for inspecting the internal structure of a SWF before editing.
    Large dumps are clipped to `max_chars` so responses stay within MCP
    transport message limits; pass `outfile` to save the complete dump.

    Args:
        swf_path: Absolute path to the SWF file
        timeout: Optional timeout in seconds (default: 60)
        outfile: Optional path to save the full tag dump to disk
        max_chars: Maximum characters returned in the response
            (default: 250000, 0 disables clipping)

    Returns:
        Dictionary with:
        - success: Whether the dump succeeded
        - swf_path: Input SWF file path
        - tag_dump: The tag listing text (clipped if truncated)
        - total_chars / truncated: Clipping info
        - full_dump_path: Path of the saved full dump (when outfile is provided)
        - message: Success message
    """
    try:
        logger.info(f"Dumping SWF tags: {swf_path}")
        return get_ffdec().dump_swf(swf_path, timeout, outfile, max_chars)
    except FFDecError as e:
        logger.error(f"SWF tag dump failed: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": f"SWF tag dump failed: {e}",
        }
    except Exception as e:
        logger.error(f"Unexpected error during SWF tag dump: {e}", exc_info=True)
        return {
            "success": False,
            "error": str(e),
            "message": f"Unexpected error: {e}",
        }


@mcp.tool()
def dump_as2(
    swf_path: str,
    export_names: bool = False,
    timeout: Optional[int] = None,
    outfile: Optional[str] = None,
    max_chars: int = 250_000,
) -> dict[str, Any]:
    """
    Dump the raw list of AS1/AS2 scripts from a SWF file.

    Large dumps are clipped to `max_chars`; pass `outfile` to save the
    complete dump.

    Args:
        swf_path: Absolute path to the SWF file
        export_names: If True, print names in the export format used by
            replace/import commands
        timeout: Optional timeout in seconds (default: 60)
        outfile: Optional path to save the full script dump to disk
        max_chars: Maximum characters returned in the response
            (default: 250000, 0 disables clipping)

    Returns:
        Dictionary with:
        - success: Whether the dump succeeded
        - swf_path: Input SWF file path
        - script_dump: The raw AS1/AS2 script listing text (clipped if truncated)
        - total_chars / truncated: Clipping info
        - full_dump_path: Path of the saved full dump (when outfile is provided)
        - message: Success message
    """
    try:
        logger.info(f"Dumping AS2 scripts: {swf_path}")
        return get_ffdec().dump_as2(swf_path, export_names, timeout, outfile, max_chars)
    except FFDecError as e:
        logger.error(f"AS2 script dump failed: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": f"AS2 script dump failed: {e}",
        }
    except Exception as e:
        logger.error(f"Unexpected error during AS2 script dump: {e}", exc_info=True)
        return {
            "success": False,
            "error": str(e),
            "message": f"Unexpected error: {e}",
        }


@mcp.tool()
def dump_as3(
    swf_path: str,
    timeout: Optional[int] = None,
    outfile: Optional[str] = None,
    max_chars: int = 250_000,
) -> dict[str, Any]:
    """
    Dump the raw list of AS3 scripts from a SWF file.

    Large dumps are clipped to `max_chars`; pass `outfile` to save the
    complete dump.

    Args:
        swf_path: Absolute path to the SWF file
        timeout: Optional timeout in seconds (default: 60)
        outfile: Optional path to save the full script dump to disk
        max_chars: Maximum characters returned in the response
            (default: 250000, 0 disables clipping)

    Returns:
        Dictionary with:
        - success: Whether the dump succeeded
        - swf_path: Input SWF file path
        - script_dump: The raw AS3 script listing text (clipped if truncated)
        - total_chars / truncated: Clipping info
        - full_dump_path: Path of the saved full dump (when outfile is provided)
        - message: Success message
    """
    try:
        logger.info(f"Dumping AS3 scripts: {swf_path}")
        return get_ffdec().dump_as3(swf_path, timeout, outfile, max_chars)
    except FFDecError as e:
        logger.error(f"AS3 script dump failed: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": f"AS3 script dump failed: {e}",
        }
    except Exception as e:
        logger.error(f"Unexpected error during AS3 script dump: {e}", exc_info=True)
        return {
            "success": False,
            "error": str(e),
            "message": f"Unexpected error: {e}",
        }


@mcp.tool()
def link_report(
    swf_path: str,
    outfile: Optional[str] = None,
    timeout: Optional[int] = None,
    max_chars: int = 250_000,
) -> dict[str, Any]:
    """
    Generate a linker report for a SWF file.

    The text response is clipped to `max_chars` when no `outfile` is given.

    Args:
        swf_path: Absolute path to the SWF file
        outfile: Optional path to save the XML report to. When omitted, the
            report text is returned directly
        timeout: Optional timeout in seconds (default: 60)
        max_chars: Maximum characters returned in the response
            (default: 250000, 0 disables clipping)

    Returns:
        Dictionary with:
        - success: Whether the report generation succeeded
        - swf_path: Input SWF file path
        - report: Report text (when outfile is omitted, clipped if truncated)
        - total_chars / truncated: Clipping info (when outfile is omitted)
        - report_path: Report file path (when outfile is provided)
        - message: Success message
    """
    try:
        logger.info(f"Generating linker report: {swf_path}")
        return get_ffdec().link_report(swf_path, outfile, timeout, max_chars)
    except FFDecError as e:
        logger.error(f"Linker report failed: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": f"Linker report failed: {e}",
        }
    except Exception as e:
        logger.error(f"Unexpected error during linker report: {e}", exc_info=True)
        return {
            "success": False,
            "error": str(e),
            "message": f"Unexpected error: {e}",
        }


@mcp.tool()
def generate_documentation(
    doc_type: str,
    outfile: Optional[str] = None,
    format: Optional[str] = "html",
    locale: Optional[str] = None,
    timeout: Optional[int] = None,
    max_chars: int = 250_000,
) -> dict[str, Any]:
    """
    Generate documentation listing AVM instructions.

    The text response is clipped to `max_chars` when no `outfile` is given.

    Args:
        doc_type: Documentation type: 'as3.pcode.instructions' (AVM2) or
            'as12.pcode.instructions' (AVM1)
        outfile: Optional output file path. When omitted, the documentation is
            returned as text
        format: Output format (currently only 'html')
        locale: Optional locale override (e.g. 'en')
        timeout: Optional timeout in seconds (default: 60)
        max_chars: Maximum characters returned in the response
            (default: 250000, 0 disables clipping)

    Returns:
        Dictionary with:
        - success: Whether documentation generation succeeded
        - doc_type: The requested documentation type
        - documentation: Documentation text (when outfile is omitted,
            clipped if truncated)
        - total_chars / truncated: Clipping info (when outfile is omitted)
        - doc_path: Documentation file path (when outfile is provided)
        - message: Success message
    """
    try:
        logger.info(f"Generating documentation: {doc_type}")
        return get_ffdec().generate_documentation(
            doc_type, outfile, format, locale, timeout, max_chars
        )
    except FFDecError as e:
        logger.error(f"Documentation generation failed: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": f"Documentation generation failed: {e}",
        }
    except Exception as e:
        logger.error(
            f"Unexpected error during documentation generation: {e}", exc_info=True
        )
        return {
            "success": False,
            "error": str(e),
            "message": f"Unexpected error: {e}",
        }


# ----------------------------------------------------------------------
# Extended tools: instance metadata
# ----------------------------------------------------------------------


@mcp.tool()
def get_instance_metadata(
    swf_path: str,
    instance: str,
    output_format: Optional[str] = None,
    key: Optional[str] = None,
    datafile: Optional[str] = None,
    timeout: Optional[int] = None,
) -> dict[str, Any]:
    """
    Read instance metadata (AMF data) from a SWF file.

    Args:
        swf_path: Absolute path to the SWF file
        instance: Name of the instance to fetch metadata from
        output_format: Output format: 'jslike' (default) or 'raw'
        key: Optional subkey to display. When present, only the value from the
            subkey is shown, otherwise the whole object value
        datafile: Optional file path to write the data to. When omitted, the
            metadata text is returned directly
        timeout: Optional timeout in seconds (default: 60)

    Returns:
        Dictionary with:
        - success: Whether reading succeeded
        - swf_path: Input SWF file path
        - instance: The instance name
        - metadata: Metadata text (when datafile is omitted)
        - datafile: Data file path (when datafile is provided)
        - message: Success message
    """
    try:
        logger.info(f"Reading instance metadata from {swf_path}: {instance}")
        return get_ffdec().get_instance_metadata(
            swf_path, instance, output_format, key, datafile, timeout
        )
    except FFDecError as e:
        logger.error(f"Instance metadata read failed: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": f"Instance metadata read failed: {e}",
        }
    except Exception as e:
        logger.error(
            f"Unexpected error during instance metadata read: {e}", exc_info=True
        )
        return {
            "success": False,
            "error": str(e),
            "message": f"Unexpected error: {e}",
        }


@mcp.tool()
def set_instance_metadata(
    swf_path: str,
    instance: str,
    value: Optional[str] = None,
    datafile: Optional[str] = None,
    key: Optional[str] = None,
    input_format: Optional[str] = None,
    outfile: Optional[str] = None,
    timeout: Optional[int] = None,
) -> dict[str, Any]:
    """
    Add or replace instance metadata (AMF data) in a SWF file.

    Args:
        swf_path: Absolute path to the SWF file
        instance: Name of the instance to set metadata on
        value: Value to set. Either value or datafile must be provided
        datafile: Optional file to read the value from
        key: Optional subkey to set the value under. When omitted, the value is
            set directly on the instance
        input_format: Input format: 'jslike' (default) or 'raw'
        outfile: Output SWF path. When omitted, the original file is overwritten
        timeout: Optional timeout in seconds (default: 60)

    Returns:
        Dictionary with:
        - success: Whether setting succeeded
        - swf_path: Input SWF file path
        - output_path: Resulting SWF path
        - instance: The instance name
        - message: Success message
    """
    try:
        logger.info(f"Setting instance metadata in {swf_path}: {instance}")
        return get_ffdec().set_instance_metadata(
            swf_path, instance, value, datafile, key, input_format, outfile, timeout
        )
    except FFDecError as e:
        logger.error(f"Instance metadata set failed: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": f"Instance metadata set failed: {e}",
        }
    except Exception as e:
        logger.error(
            f"Unexpected error during instance metadata set: {e}", exc_info=True
        )
        return {
            "success": False,
            "error": str(e),
            "message": f"Unexpected error: {e}",
        }


@mcp.tool()
def remove_instance_metadata(
    swf_path: str,
    instance: str,
    key: Optional[str] = None,
    outfile: Optional[str] = None,
    timeout: Optional[int] = None,
) -> dict[str, Any]:
    """
    Remove instance metadata (AMF data) from a SWF file.

    Args:
        swf_path: Absolute path to the SWF file
        instance: Name of the instance to remove metadata from
        key: Optional subkey to remove. When omitted, all metadata of the
            instance is removed
        outfile: Output SWF path. When omitted, the original file is overwritten
        timeout: Optional timeout in seconds (default: 60)

    Returns:
        Dictionary with:
        - success: Whether removal succeeded
        - swf_path: Input SWF file path
        - output_path: Resulting SWF path
        - instance: The instance name
        - message: Success message
    """
    try:
        logger.info(f"Removing instance metadata from {swf_path}: {instance}")
        return get_ffdec().remove_instance_metadata(
            swf_path, instance, key, outfile, timeout
        )
    except FFDecError as e:
        logger.error(f"Instance metadata removal failed: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": f"Instance metadata removal failed: {e}",
        }
    except Exception as e:
        logger.error(
            f"Unexpected error during instance metadata removal: {e}", exc_info=True
        )
        return {
            "success": False,
            "error": str(e),
            "message": f"Unexpected error: {e}",
        }


# ----------------------------------------------------------------------
# Extended tools: header and compression
# ----------------------------------------------------------------------


@mcp.tool()
def set_header(
    swf_path: str,
    settings: Optional[dict[str, Any]] = None,
    outfile: Optional[str] = None,
    timeout: Optional[int] = None,
) -> dict[str, Any]:
    """
    Print or set SWF header values.

    Args:
        swf_path: Absolute path to the SWF file
        settings: Optional dict of header keys to set. Valid keys: 'version',
            'gfx', 'displayrect' (e.g. '[0,0,800,600]'), 'width', 'height',
            'framecount', 'framerate'. When omitted, the current header is
            printed instead
        outfile: Output SWF path (required when settings are provided)
        timeout: Optional timeout in seconds (default: 60)

    Returns:
        Dictionary with:
        - success: Whether the operation succeeded
        - swf_path: Input SWF file path
        - output_path: Resulting SWF path (when settings are provided)
        - settings: The applied header settings (when provided)
        - Header values (when printing)
        - message: Success message
    """
    try:
        logger.info(f"Header operation on {swf_path}")
        return get_ffdec().set_header(swf_path, settings, outfile, timeout)
    except FFDecError as e:
        logger.error(f"Header operation failed: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": f"Header operation failed: {e}",
        }
    except Exception as e:
        logger.error(f"Unexpected error during header operation: {e}", exc_info=True)
        return {
            "success": False,
            "error": str(e),
            "message": f"Unexpected error: {e}",
        }


@mcp.tool()
def compress_swf(
    swf_path: str,
    output_path: str,
    action: str = "compress",
    method: Optional[str] = None,
    timeout: Optional[int] = None,
) -> dict[str, Any]:
    """
    Compress or decompress a SWF file.

    Args:
        swf_path: Absolute path to the SWF file
        output_path: Path for the resulting SWF file
        action: 'compress' or 'decompress' (default: 'compress')
        method: Compression method for compress: 'zlib' (default) or 'lzma'
        timeout: Optional timeout in seconds (default: 60)

    Returns:
        Dictionary with:
        - success: Whether the operation succeeded
        - swf_path: Input SWF file path
        - output_path: Resulting SWF path
        - action: The performed action
        - message: Success message
    """
    try:
        logger.info(f"SWF {action}: {swf_path} -> {output_path}")
        return get_ffdec().compress_swf(swf_path, output_path, action, method, timeout)
    except FFDecError as e:
        logger.error(f"SWF {action} failed: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": f"SWF {action} failed: {e}",
        }
    except Exception as e:
        logger.error(f"Unexpected error during SWF {action}: {e}", exc_info=True)
        return {
            "success": False,
            "error": str(e),
            "message": f"Unexpected error: {e}",
        }


@mcp.tool()
def encrypt_swf(
    swf_path: str, output_path: str, timeout: Optional[int] = None
) -> dict[str, Any]:
    """
    Encrypt a SWF file with HARMAN Air encryption.

    Args:
        swf_path: Absolute path to the SWF file
        output_path: Path for the encrypted SWF file
        timeout: Optional timeout in seconds (default: 60)

    Returns:
        Dictionary with:
        - success: Whether encryption succeeded
        - swf_path: Input SWF file path
        - output_path: Resulting SWF path
        - message: Success message
    """
    try:
        logger.info(f"Encrypting SWF: {swf_path} -> {output_path}")
        return get_ffdec().encrypt_swf(swf_path, output_path, timeout)
    except FFDecError as e:
        logger.error(f"SWF encryption failed: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": f"SWF encryption failed: {e}",
        }
    except Exception as e:
        logger.error(f"Unexpected error during SWF encryption: {e}", exc_info=True)
        return {
            "success": False,
            "error": str(e),
            "message": f"Unexpected error: {e}",
        }


@mcp.tool()
def decrypt_swf(
    swf_path: str, output_path: str, timeout: Optional[int] = None
) -> dict[str, Any]:
    """
    Decrypt a HARMAN Air encrypted SWF file.

    Args:
        swf_path: Absolute path to the encrypted SWF file
        output_path: Path for the decrypted SWF file
        timeout: Optional timeout in seconds (default: 60)

    Returns:
        Dictionary with:
        - success: Whether decryption succeeded
        - swf_path: Input SWF file path
        - output_path: Resulting SWF path
        - message: Success message
    """
    try:
        logger.info(f"Decrypting SWF: {swf_path} -> {output_path}")
        return get_ffdec().decrypt_swf(swf_path, output_path, timeout)
    except FFDecError as e:
        logger.error(f"SWF decryption failed: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": f"SWF decryption failed: {e}",
        }
    except Exception as e:
        logger.error(f"Unexpected error during SWF decryption: {e}", exc_info=True)
        return {
            "success": False,
            "error": str(e),
            "message": f"Unexpected error: {e}",
        }


# ----------------------------------------------------------------------
# Extended tools: SWF editing (replace / remove / import)
# ----------------------------------------------------------------------


@mcp.tool()
def replace_asset(
    swf_path: str,
    output_path: str,
    import_file: str,
    character_id: Optional[int] = None,
    script_name: Optional[str] = None,
    format: Optional[str] = None,
    method_body_index: Optional[int] = None,
    nofill: bool = False,
    start_frame: Optional[int] = None,
    timeout: Optional[int] = None,
) -> dict[str, Any]:
    """
    Replace the data of a BinaryData, Image, Shape, Text, Font, Sound tag or
    Script in a SWF file.

    Args:
        swf_path: Absolute path to the SWF file
        output_path: Path for the resulting SWF file
        import_file: File containing the new data
        character_id: Character id of the tag to replace
        script_name: Script name to replace (for AS3 scripts). Provide exactly
            one of character_id or script_name
        format: Optional format for Image and Shape tags: 'lossless',
            'lossless2', 'jpeg2', 'jpeg3', 'jpeg4'
        method_body_index: Required when the imported entity is AS3 P-code
        nofill: Only valid for shape replace
        start_frame: Sound range start frame (for sound streams)
        timeout: Optional timeout in seconds (default: 60)

    Returns:
        Dictionary with:
        - success: Whether replacement succeeded
        - swf_path: Input SWF file path
        - output_path: Resulting SWF path
        - selector: The character id or script name used
        - message: Success message
    """
    try:
        logger.info(f"Replacing asset in {swf_path} -> {output_path}")
        return get_ffdec().replace_asset(
            swf_path,
            output_path,
            import_file,
            character_id,
            script_name,
            format,
            method_body_index,
            nofill,
            start_frame,
            timeout,
        )
    except FFDecError as e:
        logger.error(f"Asset replacement failed: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": f"Asset replacement failed: {e}",
        }
    except Exception as e:
        logger.error(f"Unexpected error during asset replacement: {e}", exc_info=True)
        return {
            "success": False,
            "error": str(e),
            "message": f"Unexpected error: {e}",
        }


@mcp.tool()
def replace_alpha(
    swf_path: str,
    output_path: str,
    pairs: list,
    timeout: Optional[int] = None,
) -> dict[str, Any]:
    """
    Replace the alpha channel of JPEG3/JPEG4 image tags in a SWF file.

    The alpha image must have exactly the same dimensions as the target JPEG.

    Args:
        swf_path: Absolute path to the SWF file
        output_path: Path for the resulting SWF file
        pairs: List of [image_id, import_data_file] pairs, e.g.
            [[10, "C:/new_alpha.png"]]
        timeout: Optional timeout in seconds (default: 60)

    Returns:
        Dictionary with:
        - success: Whether replacement succeeded
        - swf_path: Input SWF file path
        - output_path: Resulting SWF path
        - replaced_count: Number of images processed
        - message: Success message
    """
    try:
        logger.info(f"Replacing alpha in {swf_path} -> {output_path}")
        return get_ffdec().replace_alpha(swf_path, output_path, pairs, timeout)
    except FFDecError as e:
        logger.error(f"Alpha replacement failed: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": f"Alpha replacement failed: {e}",
        }
    except Exception as e:
        logger.error(f"Unexpected error during alpha replacement: {e}", exc_info=True)
        return {
            "success": False,
            "error": str(e),
            "message": f"Unexpected error: {e}",
        }


@mcp.tool()
def replace_character(
    swf_path: str,
    output_path: str,
    pairs: list,
    timeout: Optional[int] = None,
) -> dict[str, Any]:
    """
    Replace character tags with other characters from the same SWF file.

    Args:
        swf_path: Absolute path to the SWF file
        output_path: Path for the resulting SWF file
        pairs: List of [character_id, new_character_id] pairs, e.g. [[5, 12]]
        timeout: Optional timeout in seconds (default: 60)

    Returns:
        Dictionary with:
        - success: Whether replacement succeeded
        - swf_path: Input SWF file path
        - output_path: Resulting SWF path
        - replaced_count: Number of characters replaced
        - message: Success message
    """
    try:
        logger.info(f"Replacing characters in {swf_path} -> {output_path}")
        return get_ffdec().replace_character(swf_path, output_path, pairs, timeout)
    except FFDecError as e:
        logger.error(f"Character replacement failed: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": f"Character replacement failed: {e}",
        }
    except Exception as e:
        logger.error(
            f"Unexpected error during character replacement: {e}", exc_info=True
        )
        return {
            "success": False,
            "error": str(e),
            "message": f"Unexpected error: {e}",
        }


@mcp.tool()
def replace_character_ids(
    swf_path: str,
    output_path: str,
    pairs: Optional[list] = None,
    mode: Optional[str] = None,
    timeout: Optional[int] = None,
) -> dict[str, Any]:
    """
    Replace character ids in bulk, or pack/sort them in a SWF file.

    Args:
        swf_path: Absolute path to the SWF file
        output_path: Path for the resulting SWF file
        pairs: List of [old_id, new_id] pairs, e.g. [[1, 4], [3, 2]]. Used when
            mode is omitted
        mode: Bulk operation: 'pack' (remove gaps between ids, e.g. 1,4,3 ->
            1,3,2) or 'sort' (assign increasing ids + pack)
        timeout: Optional timeout in seconds (default: 60)

    Returns:
        Dictionary with:
        - success: Whether the operation succeeded
        - swf_path: Input SWF file path
        - output_path: Resulting SWF path
        - message: Success message
    """
    try:
        logger.info(f"Replacing character ids in {swf_path} -> {output_path}")
        return get_ffdec().replace_character_ids(
            swf_path, output_path, pairs, mode, timeout
        )
    except FFDecError as e:
        logger.error(f"Character id replacement failed: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": f"Character id replacement failed: {e}",
        }
    except Exception as e:
        logger.error(
            f"Unexpected error during character id replacement: {e}", exc_info=True
        )
        return {
            "success": False,
            "error": str(e),
            "message": f"Unexpected error: {e}",
        }


@mcp.tool()
def remove_tags(
    swf_path: str,
    output_path: str,
    tag_indexes: list[int],
    timeout: Optional[int] = None,
) -> dict[str, Any]:
    """
    Remove tags (by index on the main timeline) from a SWF file.

    Args:
        swf_path: Absolute path to the SWF file
        output_path: Path for the resulting SWF file
        tag_indexes: List of tag indexes to remove, e.g. [3, 7]
        timeout: Optional timeout in seconds (default: 60)

    Returns:
        Dictionary with:
        - success: Whether removal succeeded
        - swf_path: Input SWF file path
        - output_path: Resulting SWF path
        - removed_count: Number of tags removed
        - message: Success message
    """
    try:
        logger.info(f"Removing tags from {swf_path} -> {output_path}")
        return get_ffdec().remove_tags(swf_path, output_path, tag_indexes, timeout)
    except FFDecError as e:
        logger.error(f"Tag removal failed: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": f"Tag removal failed: {e}",
        }
    except Exception as e:
        logger.error(f"Unexpected error during tag removal: {e}", exc_info=True)
        return {
            "success": False,
            "error": str(e),
            "message": f"Unexpected error: {e}",
        }


@mcp.tool()
def remove_characters(
    swf_path: str,
    output_path: str,
    character_ids: list[int],
    with_dependencies: bool = False,
    timeout: Optional[int] = None,
) -> dict[str, Any]:
    """
    Remove character tags from a SWF file.

    Args:
        swf_path: Absolute path to the SWF file
        output_path: Path for the resulting SWF file
        character_ids: List of character ids to remove, e.g. [5, 8]
        with_dependencies: If True, also remove dependent characters
        timeout: Optional timeout in seconds (default: 60)

    Returns:
        Dictionary with:
        - success: Whether removal succeeded
        - swf_path: Input SWF file path
        - output_path: Resulting SWF path
        - removed_count: Number of characters removed
        - message: Success message
    """
    try:
        logger.info(f"Removing characters from {swf_path} -> {output_path}")
        return get_ffdec().remove_characters(
            swf_path, output_path, character_ids, with_dependencies, timeout
        )
    except FFDecError as e:
        logger.error(f"Character removal failed: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": f"Character removal failed: {e}",
        }
    except Exception as e:
        logger.error(
            f"Unexpected error during character removal: {e}", exc_info=True
        )
        return {
            "success": False,
            "error": str(e),
            "message": f"Unexpected error: {e}",
        }


@mcp.tool()
def import_assets(
    swf_path: str,
    output_path: str,
    asset_type: str,
    folder: str,
    nofill: bool = False,
    timeout: Optional[int] = None,
) -> dict[str, Any]:
    """
    Bulk import assets into a SWF file (pairs with extract_assets exports).

    Args:
        swf_path: Absolute path to the SWF file
        output_path: Path for the resulting SWF file
        asset_type: One of 'script', 'images', 'sounds', 'movies', 'shapes',
            'sprites', 'text', 'symbolclass'
        folder: Folder containing the previously exported items to import. For
            'symbolclass', the folder must contain a symbols.csv mapping file
        nofill: Only valid for 'shapes' import
        timeout: Optional timeout in seconds (default: 60)

    Returns:
        Dictionary with:
        - success: Whether import succeeded
        - swf_path: Input SWF file path
        - output_path: Resulting SWF path
        - asset_type: The imported asset type
        - message: Success message
    """
    try:
        logger.info(f"Importing {asset_type} into {swf_path} -> {output_path}")
        return get_ffdec().import_assets(
            swf_path, output_path, asset_type, folder, nofill, timeout
        )
    except FFDecError as e:
        logger.error(f"Asset import failed: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": f"Asset import failed: {e}",
        }
    except Exception as e:
        logger.error(f"Unexpected error during asset import: {e}", exc_info=True)
        return {
            "success": False,
            "error": str(e),
            "message": f"Unexpected error: {e}",
        }


# ----------------------------------------------------------------------
# Extended tools: misc SWF processing
# ----------------------------------------------------------------------


@mcp.tool()
def enable_debugging(
    swf_path: str,
    output_path: str,
    inject_as3: bool = False,
    generate_swd: bool = False,
    pcode: bool = False,
    timeout: Optional[int] = None,
) -> dict[str, Any]:
    """
    Enable debugging in a SWF file.

    Args:
        swf_path: Absolute path to the SWF file
        output_path: Path for the resulting SWF file
        inject_as3: If True, inject debugfile/debugline instructions to match
            decompiled/P-code source
        generate_swd: If True, generate an SWD file for AS1/AS2 debugging
        pcode: If True, handle lines as P-code lines (all P-code lines injected)
        timeout: Optional timeout in seconds (default: 60)

    Returns:
        Dictionary with:
        - success: Whether the operation succeeded
        - swf_path: Input SWF file path
        - output_path: Resulting SWF path
        - message: Success message
    """
    try:
        logger.info(f"Enabling debugging in {swf_path} -> {output_path}")
        return get_ffdec().enable_debugging(
            swf_path, output_path, inject_as3, generate_swd, pcode, timeout
        )
    except FFDecError as e:
        logger.error(f"Debugging setup failed: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": f"Debugging setup failed: {e}",
        }
    except Exception as e:
        logger.error(f"Unexpected error during debugging setup: {e}", exc_info=True)
        return {
            "success": False,
            "error": str(e),
            "message": f"Unexpected error: {e}",
        }


@mcp.tool()
def rename_invalid_identifiers(
    swf_path: str,
    output_path: str,
    mode: str = "typeNumber",
    timeout: Optional[int] = None,
) -> dict[str, Any]:
    """
    Rename invalid identifiers (e.g. from obfuscated code) in a SWF file.

    Args:
        swf_path: Absolute path to the SWF file
        output_path: Path for the resulting SWF file
        mode: Renaming mode: 'typeNumber' or 'randomWord'
        timeout: Optional timeout in seconds (default: 60)

    Returns:
        Dictionary with:
        - success: Whether renaming succeeded
        - swf_path: Input SWF file path
        - output_path: Resulting SWF path
        - mode: The renaming mode used
        - message: Success message
    """
    try:
        logger.info(f"Renaming invalid identifiers in {swf_path} -> {output_path}")
        return get_ffdec().rename_invalid_identifiers(
            swf_path, output_path, mode, timeout
        )
    except FFDecError as e:
        logger.error(f"Identifier renaming failed: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": f"Identifier renaming failed: {e}",
        }
    except Exception as e:
        logger.error(
            f"Unexpected error during identifier renaming: {e}", exc_info=True
        )
        return {
            "success": False,
            "error": str(e),
            "message": f"Unexpected error: {e}",
        }


# ----------------------------------------------------------------------
# Extended tools: conversions
# ----------------------------------------------------------------------


@mcp.tool()
def swf_to_xml(
    swf_path: str,
    output_path: str,
    external: Optional[str] = None,
    timeout: Optional[int] = None,
) -> dict[str, Any]:
    """
    Convert a SWF file to XML (full tag-level representation).

    The XML can be edited and converted back with xml_to_swf.

    Args:
        swf_path: Absolute path to the SWF file
        output_path: Path for the XML file
        external: Optional -external value: comma separated list such as
            'as12script,image,definesound' or 'all'
        timeout: Optional timeout in seconds (default: 60)

    Returns:
        Dictionary with:
        - success: Whether conversion succeeded
        - swf_path: Input SWF file path
        - output_path: XML output path
        - message: Success message
    """
    try:
        logger.info(f"Converting SWF to XML: {swf_path} -> {output_path}")
        return get_ffdec().swf_to_xml(swf_path, output_path, external, timeout)
    except FFDecError as e:
        logger.error(f"SWF to XML conversion failed: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": f"SWF to XML conversion failed: {e}",
        }
    except Exception as e:
        logger.error(f"Unexpected error during SWF to XML conversion: {e}", exc_info=True)
        return {
            "success": False,
            "error": str(e),
            "message": f"Unexpected error: {e}",
        }


@mcp.tool()
def xml_to_swf(
    input_path: str, output_path: str, timeout: Optional[int] = None
) -> dict[str, Any]:
    """
    Convert an XML file (exported with swf_to_xml) back to a SWF file.

    Args:
        input_path: Absolute path to the XML file
        output_path: Path for the resulting SWF file
        timeout: Optional timeout in seconds (default: 60)

    Returns:
        Dictionary with:
        - success: Whether conversion succeeded
        - input_path: Input XML file path
        - output_path: Resulting SWF path
        - message: Success message
    """
    try:
        logger.info(f"Converting XML to SWF: {input_path} -> {output_path}")
        return get_ffdec().xml_to_swf(input_path, output_path, timeout)
    except FFDecError as e:
        logger.error(f"XML to SWF conversion failed: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": f"XML to SWF conversion failed: {e}",
        }
    except Exception as e:
        logger.error(f"Unexpected error during XML to SWF conversion: {e}", exc_info=True)
        return {
            "success": False,
            "error": str(e),
            "message": f"Unexpected error: {e}",
        }


@mcp.tool()
def swf_to_exe(
    swf_path: str,
    output_path: str,
    export_mode: str = "projector_win",
    timeout: Optional[int] = None,
) -> dict[str, Any]:
    """
    Export a SWF to a standalone executable file.

    Args:
        swf_path: Absolute path to the SWF file
        output_path: Path for the resulting executable
        export_mode: One of 'wrapper', 'projector_win', 'projector_mac',
            'projector_linux' (default: 'projector_win')
        timeout: Optional timeout in seconds (default: 60)

    Returns:
        Dictionary with:
        - success: Whether export succeeded
        - swf_path: Input SWF file path
        - output_path: Resulting executable path
        - export_mode: The export mode used
        - message: Success message
    """
    try:
        logger.info(f"Exporting SWF to executable: {swf_path} -> {output_path}")
        return get_ffdec().swf_to_exe(swf_path, output_path, export_mode, timeout)
    except FFDecError as e:
        logger.error(f"SWF to executable export failed: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": f"SWF to executable export failed: {e}",
        }
    except Exception as e:
        logger.error(
            f"Unexpected error during SWF to executable export: {e}", exc_info=True
        )
        return {
            "success": False,
            "error": str(e),
            "message": f"Unexpected error: {e}",
        }


@mcp.tool()
def swf_to_iggy(
    swf_path: str,
    output_path: str,
    layout: Optional[str] = None,
    timeout: Optional[int] = None,
) -> dict[str, Any]:
    """
    Convert a SWF file to an Iggy (Scaleform) file.

    Args:
        swf_path: Absolute path to the SWF file
        output_path: Path for the resulting Iggy file
        layout: Optional layout: '32_legacy', '32' or '64' (default)
        timeout: Optional timeout in seconds (default: 60)

    Returns:
        Dictionary with:
        - success: Whether conversion succeeded
        - swf_path: Input SWF file path
        - output_path: Resulting Iggy path
        - layout: The layout used
        - message: Success message
    """
    try:
        logger.info(f"Converting SWF to Iggy: {swf_path} -> {output_path}")
        return get_ffdec().swf_to_iggy(swf_path, output_path, layout, timeout)
    except FFDecError as e:
        logger.error(f"SWF to Iggy conversion failed: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": f"SWF to Iggy conversion failed: {e}",
        }
    except Exception as e:
        logger.error(f"Unexpected error during SWF to Iggy conversion: {e}", exc_info=True)
        return {
            "success": False,
            "error": str(e),
            "message": f"Unexpected error: {e}",
        }


@mcp.tool()
def iggy_to_swf(
    input_path: str, output_path: str, timeout: Optional[int] = None
) -> dict[str, Any]:
    """
    Convert an Iggy (Scaleform) file to a SWF file (layout is auto-detected).

    Args:
        input_path: Absolute path to the Iggy file
        output_path: Path for the resulting SWF file
        timeout: Optional timeout in seconds (default: 60)

    Returns:
        Dictionary with:
        - success: Whether conversion succeeded
        - input_path: Input Iggy file path
        - output_path: Resulting SWF path
        - message: Success message
    """
    try:
        logger.info(f"Converting Iggy to SWF: {input_path} -> {output_path}")
        return get_ffdec().iggy_to_swf(input_path, output_path, timeout)
    except FFDecError as e:
        logger.error(f"Iggy to SWF conversion failed: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": f"Iggy to SWF conversion failed: {e}",
        }
    except Exception as e:
        logger.error(f"Unexpected error during Iggy to SWF conversion: {e}", exc_info=True)
        return {
            "success": False,
            "error": str(e),
            "message": f"Unexpected error: {e}",
        }


@mcp.tool()
def flashpaper_to_pdf(
    swf_path: str,
    output_path: str,
    zoom: Optional[int] = None,
    timeout: Optional[int] = None,
) -> dict[str, Any]:
    """
    Convert a FlashPaper SWF file to PDF.

    Args:
        swf_path: Absolute path to the FlashPaper SWF file
        output_path: Path for the resulting PDF file
        zoom: Optional zoom level specifying image quality
        timeout: Optional timeout in seconds (default: 60)

    Returns:
        Dictionary with:
        - success: Whether conversion succeeded
        - swf_path: Input SWF file path
        - output_path: Resulting PDF path
        - message: Success message
    """
    try:
        logger.info(f"Converting FlashPaper to PDF: {swf_path} -> {output_path}")
        return get_ffdec().flashpaper_to_pdf(swf_path, output_path, zoom, timeout)
    except FFDecError as e:
        logger.error(f"FlashPaper to PDF conversion failed: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": f"FlashPaper to PDF conversion failed: {e}",
        }
    except Exception as e:
        logger.error(
            f"Unexpected error during FlashPaper to PDF conversion: {e}", exc_info=True
        )
        return {
            "success": False,
            "error": str(e),
            "message": f"Unexpected error: {e}",
        }


@mcp.tool()
def swf_to_swc(
    swf_path: str, output_path: str, timeout: Optional[int] = None
) -> dict[str, Any]:
    """
    Generate a SWC file (library) from a SWF file.

    Args:
        swf_path: Absolute path to the SWF file
        output_path: Path for the resulting SWC file
        timeout: Optional timeout in seconds (default: 60)

    Returns:
        Dictionary with:
        - success: Whether generation succeeded
        - swf_path: Input SWF file path
        - output_path: Resulting SWC path
        - message: Success message
    """
    try:
        logger.info(f"Generating SWC: {swf_path} -> {output_path}")
        return get_ffdec().swf_to_swc(swf_path, output_path, timeout)
    except FFDecError as e:
        logger.error(f"SWC generation failed: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": f"SWC generation failed: {e}",
        }
    except Exception as e:
        logger.error(f"Unexpected error during SWC generation: {e}", exc_info=True)
        return {
            "success": False,
            "error": str(e),
            "message": f"Unexpected error: {e}",
        }


@mcp.tool()
def merge_abc(
    swf_path: str, output_path: str, timeout: Optional[int] = None
) -> dict[str, Any]:
    """
    Merge all ABC tags in a SWF file into one.

    Args:
        swf_path: Absolute path to the SWF file
        output_path: Path for the merged result file
        timeout: Optional timeout in seconds (default: 60)

    Returns:
        Dictionary with:
        - success: Whether merging succeeded
        - swf_path: Input SWF file path
        - output_path: Resulting file path
        - message: Success message
    """
    try:
        logger.info(f"Merging ABC tags: {swf_path} -> {output_path}")
        return get_ffdec().merge_abc(swf_path, output_path, timeout)
    except FFDecError as e:
        logger.error(f"ABC merge failed: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": f"ABC merge failed: {e}",
        }
    except Exception as e:
        logger.error(f"Unexpected error during ABC merge: {e}", exc_info=True)
        return {
            "success": False,
            "error": str(e),
            "message": f"Unexpected error: {e}",
        }


@mcp.tool()
def clean_abc(
    input_path: str, output_path: str, timeout: Optional[int] = None
) -> dict[str, Any]:
    """
    Clean an ABC file (or SWF/GFX) by removing all unused items.

    Args:
        input_path: Absolute path to the ABC (.abc) or SWF/GFX file
        output_path: Path for the cleaned result
        timeout: Optional timeout in seconds (default: 60)

    Returns:
        Dictionary with:
        - success: Whether cleaning succeeded
        - input_path: Input file path
        - output_path: Resulting file path
        - message: Success message
    """
    try:
        logger.info(f"Cleaning ABC: {input_path} -> {output_path}")
        return get_ffdec().clean_abc(input_path, output_path, timeout)
    except FFDecError as e:
        logger.error(f"ABC cleaning failed: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": f"ABC cleaning failed: {e}",
        }
    except Exception as e:
        logger.error(f"Unexpected error during ABC cleaning: {e}", exc_info=True)
        return {
            "success": False,
            "error": str(e),
            "message": f"Unexpected error: {e}",
        }


# ----------------------------------------------------------------------
# Extended tools: utilities
# ----------------------------------------------------------------------


@mcp.tool()
def extract_swf_files(
    input_path: str,
    output_path: Optional[str] = None,
    mode: Optional[str] = None,
    nocheck: bool = False,
    timeout: Optional[int] = None,
) -> dict[str, Any]:
    """
    Extract SWF files embedded in a ZIP or other binary file.

    Args:
        input_path: Absolute path to the ZIP or binary file
        output_path: Output folder path. For 'biggest'/'first' mode this is the
            output file path, otherwise the output folder path
        mode: Extraction mode: 'all', 'biggest', 'smallest', 'first' or 'last'
        nocheck: If True, skip validation of extracted data
        timeout: Optional timeout in seconds (default: 60)

    Returns:
        Dictionary with:
        - success: Whether extraction succeeded
        - input_path: Input file path
        - output_path: Output path (when provided)
        - mode: The extraction mode used
        - message: Success message
    """
    try:
        logger.info(f"Extracting SWF files from {input_path}")
        return get_ffdec().extract_swf_files(
            input_path, output_path, mode, nocheck, timeout
        )
    except FFDecError as e:
        logger.error(f"SWF extraction failed: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": f"SWF extraction failed: {e}",
        }
    except Exception as e:
        logger.error(f"Unexpected error during SWF extraction: {e}", exc_info=True)
        return {
            "success": False,
            "error": str(e),
            "message": f"Unexpected error: {e}",
        }


@mcp.tool()
def search_memory(
    processes: list, timeout: Optional[int] = None
) -> dict[str, Any]:
    """
    Search for SWF files in the memory of running processes.

    Args:
        processes: List of process names or process ids, e.g.
            ['chrome', 1234]
        timeout: Optional timeout in seconds (default: 60)

    Returns:
        Dictionary with:
        - success: Whether the search completed
        - processes: The queried processes
        - output: Console output listing found SWF files
        - message: Success message
    """
    try:
        logger.info(f"Searching memory of processes: {processes}")
        return get_ffdec().search_memory(processes, timeout)
    except FFDecError as e:
        logger.error(f"Memory search failed: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": f"Memory search failed: {e}",
        }
    except Exception as e:
        logger.error(f"Unexpected error during memory search: {e}", exc_info=True)
        return {
            "success": False,
            "error": str(e),
            "message": f"Unexpected error: {e}",
        }


@mcp.tool()
def run_ffdec(
    args: list[str],
    timeout: Optional[int] = None,
    outfile: Optional[str] = None,
    max_chars: int = 250_000,
) -> dict[str, Any]:
    """
    Run FFDec with arbitrary command-line arguments (generic passthrough).

    Use this for any FFDec CLI capability not covered by a dedicated tool,
    e.g. ["-listconfigs"], ["-config", "decompileStatistic=true", "-dumpSWF",
    "C:/file.swf"], or ["-storeConfigFile", "config.toml"].
    Large stdout is clipped to `max_chars`; pass `outfile` to save the
    complete stdout.

    Args:
        args: FFDec command-line arguments (without the executable itself)
        timeout: Optional timeout in seconds (default: 60)
        outfile: Optional path to save the full stdout to disk
        max_chars: Maximum characters of stdout returned in the response
            (default: 250000, 0 disables clipping)

    Returns:
        Dictionary with:
        - success: Whether execution completed
        - args: The arguments used
        - stdout: Standard output (clipped if truncated)
        - stderr: Standard error
        - returncode: Process exit code
        - total_chars / truncated: Clipping info
        - full_output_path: Path of the saved full stdout (when outfile provided)
        - message: Success message
    """
    try:
        logger.info(f"Running FFDec with args: {args}")
        return get_ffdec().run_ffdec(args, timeout, outfile, max_chars)
    except FFDecError as e:
        logger.error(f"FFDec execution failed: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": f"FFDec execution failed: {e}",
        }
    except Exception as e:
        logger.error(f"Unexpected error during FFDec execution: {e}", exc_info=True)
        return {
            "success": False,
            "error": str(e),
            "message": f"Unexpected error: {e}",
        }

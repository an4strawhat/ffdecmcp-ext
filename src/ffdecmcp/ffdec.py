"""FFDec execution wrapper."""

import logging
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any, Optional

from .aircrypto import harman_decrypt, harman_encrypt, is_encrypted
from .config import FFDecConfig, FFDecMode, get_config
from .utils import normalize_path, validate_output_dir, validate_swf_path

# Configure logging to stderr
logger = logging.getLogger(__name__)


class FFDecError(Exception):
    """Base exception for FFDec errors."""

    pass


class FFDecTimeoutError(FFDecError):
    """Raised when FFDec execution times out."""

    pass


class FFDecExecutionError(FFDecError):
    """Raised when FFDec execution fails."""

    pass


class FFDecWrapper:
    """Wrapper for executing FFDec commands."""

    def __init__(self, config: Optional[FFDecConfig] = None):
        """
        Initialize FFDec wrapper.

        Args:
            config: FFDec configuration (auto-detected if not provided)
        """
        self.config = config or get_config()
        logger.info(
            f"FFDecWrapper initialized with mode={self.config.mode.value}, "
            f"path={self.config.path}"
        )

    def _build_command(self, args: list[str]) -> list[str]:
        """
        Build command based on execution mode.

        Args:
            args: FFDec arguments

        Returns:
            Complete command list
        """
        if self.config.mode == FFDecMode.WSL:
            # WSL execution: wsl <ffdec_path> <args>
            return ["wsl", self.config.path] + args

        elif self.config.mode == FFDecMode.JAR:
            # JAR execution: java -jar <jar_path> <args>
            # Use absolute path so cwd can be set to jar's directory (for classpath resolution)
            jar_path = str(Path(self.config.path).resolve())
            return ["java", "-Djava.awt.headless=true", "-jar", jar_path] + args

        else:  # NATIVE
            # Native execution: <binary_path> <args>
            return [self.config.path] + args

    def _execute(
        self,
        args: list[str],
        timeout: Optional[int] = None,
        check_returncode: bool = True,
    ) -> subprocess.CompletedProcess:
        """
        Execute FFDec command.

        Args:
            args: FFDec arguments
            timeout: Timeout in seconds (uses config default if not specified)
            check_returncode: If True, raise exception on non-zero return code

        Returns:
            CompletedProcess result

        Raises:
            FFDecTimeoutError: If execution times out
            FFDecExecutionError: If execution fails
        """
        timeout = timeout or self.config.timeout
        command = self._build_command(args)

        logger.info(f"Executing FFDec command: {' '.join(command)}")

        # Set cwd to jar directory for classpath resolution in JAR mode
        cwd = None
        if self.config.mode == FFDecMode.JAR:
            cwd = str(Path(self.config.path).resolve().parent)

        try:
            # Execute command
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=timeout,
                cwd=cwd,
                creationflags=(
                    subprocess.CREATE_NO_WINDOW
                    if sys.platform == "win32"
                    else 0
                ),
            )

            # Log output
            if result.stdout:
                logger.debug(f"FFDec stdout: {result.stdout}")
            if result.stderr:
                logger.debug(f"FFDec stderr: {result.stderr}")

            # Check return code
            if check_returncode and result.returncode != 0:
                error_msg = result.stderr or result.stdout or "Unknown error"
                raise FFDecExecutionError(
                    f"FFDec command failed with return code {result.returncode}: {error_msg}"
                )

            return result

        except subprocess.TimeoutExpired as e:
            raise FFDecTimeoutError(
                f"FFDec command timed out after {timeout} seconds. "
                f"Try increasing FFDEC_TIMEOUT or simplifying the operation."
            ) from e

        except FileNotFoundError as e:
            raise FFDecExecutionError(
                f"FFDec executable not found: {self.config.path}. "
                f"Please check FFDEC_PATH configuration."
            ) from e

        except Exception as e:
            raise FFDecExecutionError(f"Failed to execute FFDec: {e}") from e

    def _normalize_paths(self, *paths: str) -> list[str]:
        """
        Normalize paths for FFDec execution.

        Args:
            paths: Paths to normalize

        Returns:
            List of normalized paths
        """
        use_wsl = self.config.mode == FFDecMode.WSL
        return [normalize_path(p, for_wsl=use_wsl) for p in paths]

    def decompile_swf(
        self, swf_path: str, output_dir: str, timeout: Optional[int] = None
    ) -> dict[str, Any]:
        """
        Decompile all ActionScript from SWF file.

        Args:
            swf_path: Path to SWF file
            output_dir: Output directory for decompiled scripts
            timeout: Timeout in seconds

        Returns:
            Result dictionary with status and details

        Raises:
            FFDecError: If decompilation fails
        """
        # Validate inputs
        is_valid, error = validate_swf_path(swf_path)
        if not is_valid:
            raise FFDecError(error)

        is_valid, error = validate_output_dir(output_dir, create=True)
        if not is_valid:
            raise FFDecError(error)

        # Normalize paths
        swf_norm, output_norm = self._normalize_paths(swf_path, output_dir)

        # Build command: ffdec -timeout <timeout> -onerror ignore -export script <output_dir> <swf_path>
        timeout_val = timeout or self.config.timeout
        args = [
            "-timeout",
            str(timeout_val),
            "-onerror",
            "ignore",
            "-export",
            "script",
            output_norm,
            swf_norm,
        ]

        # Execute
        try:
            result = self._execute(args, timeout=timeout_val)

            # Count output files
            output_path = Path(output_dir)
            script_files = list(output_path.rglob("*.as"))

            return {
                "success": True,
                "swf_path": swf_path,
                "output_dir": output_dir,
                "script_count": len(script_files),
                "message": f"Successfully decompiled {len(script_files)} ActionScript files",
            }

        except FFDecError:
            raise
        except Exception as e:
            raise FFDecExecutionError(f"Decompilation failed: {e}") from e

    def extract_actionscript(
        self,
        swf_path: str,
        class_names: list[str],
        output_dir: str,
        timeout: Optional[int] = None,
    ) -> dict[str, Any]:
        """
        Extract specific ActionScript classes by name.

        Args:
            swf_path: Path to SWF file
            class_names: List of class names to extract
            output_dir: Output directory for extracted classes
            timeout: Timeout in seconds

        Returns:
            Result dictionary with status and details

        Raises:
            FFDecError: If extraction fails
        """
        # Validate inputs
        if not class_names:
            raise FFDecError("No class names provided")

        is_valid, error = validate_swf_path(swf_path)
        if not is_valid:
            raise FFDecError(error)

        is_valid, error = validate_output_dir(output_dir, create=True)
        if not is_valid:
            raise FFDecError(error)

        # Normalize paths
        swf_norm, output_norm = self._normalize_paths(swf_path, output_dir)

        # Build command: ffdec -selectclass <classes> -export script <output_dir> <swf_path>
        timeout_val = timeout or self.config.timeout
        class_list = ",".join(class_names)

        args = [
            "-selectclass",
            class_list,
            "-export",
            "script",
            output_norm,
            swf_norm,
        ]

        # Execute
        try:
            result = self._execute(args, timeout=timeout_val)

            # Count output files
            output_path = Path(output_dir)
            script_files = list(output_path.rglob("*.as"))

            return {
                "success": True,
                "swf_path": swf_path,
                "output_dir": output_dir,
                "requested_classes": class_names,
                "extracted_files": len(script_files),
                "message": f"Successfully extracted {len(script_files)} ActionScript files",
            }

        except FFDecError:
            raise
        except Exception as e:
            raise FFDecExecutionError(f"ActionScript extraction failed: {e}") from e

    def list_symbols(self, swf_path: str) -> dict[str, Any]:
        """
        List all classes and symbols in SWF file.

        Args:
            swf_path: Path to SWF file

        Returns:
            Dictionary with packages, classes, and symbols

        Raises:
            FFDecError: If listing fails
        """
        # Validate input
        is_valid, error = validate_swf_path(swf_path)
        if not is_valid:
            raise FFDecError(error)

        # Normalize path
        swf_norm = self._normalize_paths(swf_path)[0]

        # Try AS3 first
        try:
            args = ["-dumpAS3", swf_norm]
            result = self._execute(args, check_returncode=False)

            if result.returncode == 0 and result.stdout:
                return self._parse_symbol_dump(result.stdout, "AS3")

        except FFDecError:
            pass

        # Fallback to AS2
        try:
            args = ["-dumpAS2", swf_norm]
            result = self._execute(args, check_returncode=False)

            if result.returncode == 0 and result.stdout:
                return self._parse_symbol_dump(result.stdout, "AS2")

        except FFDecError:
            pass

        # If both failed, return empty result
        return {
            "success": True,
            "swf_path": swf_path,
            "type": "Unknown",
            "packages": {},
            "classes": [],
            "total_symbols": 0,
            "message": "No ActionScript symbols found (may not contain AS2/AS3 code)",
        }

    def _parse_symbol_dump(self, dump: str, as_type: str) -> dict[str, Any]:
        """
        Parse FFDec symbol dump output.

        Args:
            dump: Raw dump output
            as_type: ActionScript type (AS2 or AS3)

        Returns:
            Parsed symbol dictionary
        """
        packages = {}
        classes = []

        for line in dump.split("\n"):
            line = line.strip()
            if not line:
                continue

            if as_type == "AS3":
                # FFDec -dumpAS3 prints: "<fully.qualified.ClassName> <index>"
                m = re.match(r"^([\w.:+$]+)\s+\d+\s*$", line)
                if not m:
                    continue
                full_class = m.group(1)
            else:
                # Legacy AS2 heuristic: lines containing "class <name>"
                class_match = re.search(r"class\s+([\w.]+)", line)
                if not class_match:
                    continue
                full_class = class_match.group(1)

            classes.append(full_class)

            # Extract package
            if "." in full_class:
                package = ".".join(full_class.split(".")[:-1])
                class_name = full_class.split(".")[-1]
            else:
                package = "(default)"
                class_name = full_class

            if package not in packages:
                packages[package] = []
            packages[package].append(class_name)

        return {
            "success": True,
            "type": as_type,
            "packages": packages,
            "classes": classes,
            "total_symbols": len(classes),
            "message": f"Found {len(classes)} {as_type} classes in {len(packages)} packages",
        }

    def extract_assets(
        self,
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
        Extract assets from SWF file.

        Args:
            swf_path: Path to SWF file
            output_dir: Output directory for extracted assets
            asset_types: List of asset types (image, sound, font, font4, shape,
                morphshape, movie, frame, sprite, button, binaryData, symbolClass,
                text, all, fla, xfl)
            formats: Optional list of -format values (e.g. ["script:pcode", "shape:svg"])
            select: Optional -select frame ranges string (e.g. "1-5" or "all:12-29")
            select_ids: Optional -selectid character ranges string (e.g. "1-5")
            zoom: Optional zoom level applied during export
            ignore_background: If True, ignore SWF background color (transparent frames)
            onerror: Optional error handling mode (abort, retry, ignore)
            onerror_retries: Retry count when onerror is "retry"
            export_timeout: Optional total export timeout in seconds
            timeout: Timeout in seconds

        Returns:
            Result dictionary with status and details

        Raises:
            FFDecError: If extraction fails
        """
        # Validate inputs
        is_valid, error = validate_swf_path(swf_path)
        if not is_valid:
            raise FFDecError(error)

        is_valid, error = validate_output_dir(output_dir, create=True)
        if not is_valid:
            raise FFDecError(error)

        # Default to all assets
        if not asset_types:
            asset_types = ["all"]

        # Validate asset types
        valid_types = {
            "image",
            "sound",
            "font",
            "font4",
            "shape",
            "morphshape",
            "movie",
            "frame",
            "sprite",
            "button",
            "binaryData",
            "symbolClass",
            "text",
            "all",
            "fla",
            "xfl",
        }
        invalid = set(asset_types) - valid_types
        if invalid:
            raise FFDecError(
                f"Invalid asset types: {invalid}. Valid: {sorted(valid_types)}"
            )

        # Validate onerror mode
        if onerror is not None and onerror not in {"abort", "retry", "ignore"}:
            raise FFDecError(
                f"Invalid onerror mode: {onerror}. Valid: abort, retry, ignore"
            )

        # Normalize paths
        swf_norm, output_norm = self._normalize_paths(swf_path, output_dir)

        # Build command: ffdec [pre-options] -export <types> <output_dir> <swf_path>
        timeout_val = timeout or self.config.timeout

        # Build pre-options
        args: list[str] = []
        if formats:
            args.extend(["-format", ",".join(formats)])
        if select:
            args.extend(["-select", select])
        if select_ids:
            args.extend(["-selectid", select_ids])
        if zoom is not None:
            args.extend(["-zoom", str(zoom)])
        if ignore_background:
            args.append("-ignorebackground")
        if export_timeout is not None:
            args.extend(["-exportTimeout", str(export_timeout)])
        if onerror is not None:
            if onerror == "retry":
                args.extend(["-onerror", "retry", str(onerror_retries)])
            else:
                args.extend(["-onerror", onerror])

        # Build export arguments (FFDec expects one comma-separated type list)
        args.extend(
            [
                "-timeout",
                str(timeout_val),
                "-export",
                ",".join(asset_types),
                output_norm,
                swf_norm,
            ]
        )

        # Execute
        try:
            result = self._execute(args, timeout=timeout_val)

            # Count output files
            output_path = Path(output_dir)
            asset_files = [
                f for f in output_path.rglob("*") if f.is_file()
            ]

            return {
                "success": True,
                "swf_path": swf_path,
                "output_dir": output_dir,
                "asset_types": asset_types,
                "extracted_count": len(asset_files),
                "message": f"Successfully extracted {len(asset_files)} assets",
            }

        except FFDecError:
            raise
        except Exception as e:
            raise FFDecExecutionError(f"Asset extraction failed: {e}") from e

    def get_swf_metadata(self, swf_path: str) -> dict[str, Any]:
        """
        Extract SWF header metadata.

        Args:
            swf_path: Path to SWF file

        Returns:
            Dictionary with SWF metadata

        Raises:
            FFDecError: If metadata extraction fails
        """
        # Validate input
        is_valid, error = validate_swf_path(swf_path)
        if not is_valid:
            raise FFDecError(error)

        # Normalize path
        swf_norm = self._normalize_paths(swf_path)[0]

        # Build command: ffdec -header <swf_path>
        args = ["-header", swf_norm]

        # Execute
        try:
            result = self._execute(args)

            # Parse header output
            metadata = self._parse_header(result.stdout)
            metadata["success"] = True
            metadata["swf_path"] = swf_path

            return metadata

        except FFDecError:
            raise
        except Exception as e:
            raise FFDecExecutionError(f"Metadata extraction failed: {e}") from e

    def _parse_header(self, header: str) -> dict[str, Any]:
        """
        Parse FFDec header output.

        Args:
            header: Raw header output

        Returns:
            Parsed metadata dictionary
        """
        metadata = {}

        # Parse header lines
        # Format: "key=value" (with optional [header] section marker)
        for line in header.split("\n"):
            line = line.strip()
            if line.startswith("[") or not line:
                continue
            if "=" in line:
                key, value = line.split("=", 1)
                key = key.strip().lower()
                value = value.strip()

                # Convert numeric values
                if value.isdigit():
                    value = int(value)
                elif re.match(r"^\d+\.\d+$", value):
                    value = float(value)

                metadata[key] = value

        return metadata

    def deobfuscate(
        self,
        swf_path: str,
        output_path: str,
        level: str = "max",
        timeout: Optional[int] = None,
    ) -> dict[str, Any]:
        """
        Deobfuscate SWF file.

        Args:
            swf_path: Path to obfuscated SWF file
            output_path: Path for deobfuscated SWF
            level: Deobfuscation level (traps, deadcode, max)
            timeout: Timeout in seconds

        Returns:
            Result dictionary with status and details

        Raises:
            FFDecError: If deobfuscation fails
        """
        # Validate inputs
        is_valid, error = validate_swf_path(swf_path)
        if not is_valid:
            raise FFDecError(error)

        # Validate level
        valid_levels = {"traps", "deadcode", "max"}
        if level not in valid_levels:
            raise FFDecError(
                f"Invalid deobfuscation level: {level}. Valid: {valid_levels}"
            )

        # Ensure output directory exists
        output_dir = str(Path(output_path).parent)
        is_valid, error = validate_output_dir(output_dir, create=True)
        if not is_valid:
            raise FFDecError(error)

        # Normalize paths
        swf_norm, output_norm = self._normalize_paths(swf_path, output_path)

        # Build command: ffdec -deobfuscate <level> <input_swf> <output_swf>
        timeout_val = timeout or self.config.timeout
        args = ["-deobfuscate", level, swf_norm, output_norm]

        # Execute
        try:
            result = self._execute(args, timeout=timeout_val)

            # Check if output file was created and is non-empty
            # (FFDec may exit 0 yet write an empty file when it cannot process)
            output_file = Path(output_path)
            if not output_file.exists() or output_file.stat().st_size == 0:
                raise FFDecExecutionError("Output file was not created")

            return {
                "success": True,
                "input_path": swf_path,
                "output_path": output_path,
                "level": level,
                "message": f"Successfully deobfuscated SWF at level '{level}'",
            }

        except FFDecError:
            raise
        except Exception as e:
            raise FFDecExecutionError(f"Deobfuscation failed: {e}") from e

    # ------------------------------------------------------------------
    # Generic helpers for extended commands
    # ------------------------------------------------------------------

    def _validate_input_file(
        self, path: str, extensions: Optional[list[str]] = None
    ) -> tuple[bool, Optional[str]]:
        """
        Validate a generic input file (any extension).

        Args:
            path: Path to the input file
            extensions: Optional list of allowed lowercase extensions (e.g. [".xml"])

        Returns:
            Tuple of (is_valid, error_message)
        """
        path_obj = Path(path)

        if not path_obj.exists():
            return False, f"File does not exist: {path}"
        if not path_obj.is_file():
            return False, f"Path is not a file: {path}"
        if not os.access(path, os.R_OK):
            return False, f"File is not readable: {path}"
        if extensions and path_obj.suffix.lower() not in extensions:
            return (
                False,
                f"File has unexpected extension (expected one of {extensions}): {path}",
            )

        return True, None

    def _run_capture(
        self,
        args: list[str],
        timeout: Optional[int] = None,
        check_returncode: bool = True,
    ) -> dict[str, Any]:
        """
        Execute FFDec and capture its console output.

        Returns:
            Dictionary with stdout, stderr and returncode
        """
        result = self._execute(
            args, timeout=timeout, check_returncode=check_returncode
        )
        return {
            "stdout": result.stdout or "",
            "stderr": result.stderr or "",
            "returncode": result.returncode,
        }

    def _run_file_to_file(
        self,
        args: list[str],
        output_path: str,
        timeout: Optional[int] = None,
    ) -> dict[str, Any]:
        """
        Execute an FFDec command that produces an output file, verifying creation.

        Note: FFDec may exit with code 0 even on some errors, so the output file
        is verified to exist and be non-empty.
        """
        result = self._execute(args, timeout=timeout)
        output = Path(output_path)
        if not output.exists() or output.stat().st_size == 0:
            raise FFDecExecutionError("Output file was not created")
        return {
            "returncode": result.returncode,
            "message": f"Output written to {output_path}",
        }

    def _ensure_output_parent(self, output_path: str) -> None:
        """Ensure the parent directory of an output file path exists."""
        is_valid, error = validate_output_dir(str(Path(output_path).parent), create=True)
        if not is_valid:
            raise FFDecError(error)

    # ------------------------------------------------------------------
    # Inspection commands (console output)
    # ------------------------------------------------------------------

    def dump_swf(self, swf_path: str, timeout: Optional[int] = None) -> dict[str, Any]:
        """
        Dump the list of SWF tags to console output.

        Args:
            swf_path: Path to SWF file
            timeout: Timeout in seconds

        Returns:
            Result dictionary with the tag dump
        """
        is_valid, error = validate_swf_path(swf_path)
        if not is_valid:
            raise FFDecError(error)

        swf_norm = self._normalize_paths(swf_path)[0]
        out = self._run_capture(
            ["-dumpSWF", swf_norm], timeout=timeout, check_returncode=False
        )
        return {
            "success": True,
            "swf_path": swf_path,
            "tag_dump": out["stdout"],
            "message": "Successfully dumped SWF tags",
        }

    def dump_as2(
        self, swf_path: str, export_names: bool = False, timeout: Optional[int] = None
    ) -> dict[str, Any]:
        """
        Dump the list of AS1/AS2 scripts to console output.

        Args:
            swf_path: Path to SWF file
            export_names: Use -exportNames to print names in export format
            timeout: Timeout in seconds

        Returns:
            Result dictionary with the script dump
        """
        is_valid, error = validate_swf_path(swf_path)
        if not is_valid:
            raise FFDecError(error)

        swf_norm = self._normalize_paths(swf_path)[0]
        args = ["-dumpAS2"]
        if export_names:
            args.append("-exportNames")
        args.append(swf_norm)

        out = self._run_capture(args, timeout=timeout, check_returncode=False)
        return {
            "success": True,
            "swf_path": swf_path,
            "script_dump": out["stdout"],
            "message": "Successfully dumped AS1/AS2 scripts",
        }

    def dump_as3(self, swf_path: str, timeout: Optional[int] = None) -> dict[str, Any]:
        """
        Dump the list of AS3 scripts to console output.

        Args:
            swf_path: Path to SWF file
            timeout: Timeout in seconds

        Returns:
            Result dictionary with the script dump
        """
        is_valid, error = validate_swf_path(swf_path)
        if not is_valid:
            raise FFDecError(error)

        swf_norm = self._normalize_paths(swf_path)[0]
        out = self._run_capture(
            ["-dumpAS3", swf_norm], timeout=timeout, check_returncode=False
        )
        return {
            "success": True,
            "swf_path": swf_path,
            "script_dump": out["stdout"],
            "message": "Successfully dumped AS3 scripts",
        }

    def link_report(
        self,
        swf_path: str,
        outfile: Optional[str] = None,
        timeout: Optional[int] = None,
    ) -> dict[str, Any]:
        """
        Generate a linker report for a SWF file.

        Args:
            swf_path: Path to SWF file
            outfile: Optional path to save the XML report to (stdout when omitted)
            timeout: Timeout in seconds

        Returns:
            Result dictionary with the report text or file path
        """
        is_valid, error = validate_swf_path(swf_path)
        if not is_valid:
            raise FFDecError(error)

        swf_norm = self._normalize_paths(swf_path)[0]
        args = ["-linkReport"]
        if outfile:
            self._ensure_output_parent(outfile)
            args.extend(["-outfile", self._normalize_paths(outfile)[0]])
        args.append(swf_norm)

        out = self._run_capture(args, timeout=timeout)
        result: dict[str, Any] = {"success": True, "swf_path": swf_path}
        if outfile:
            result["report_path"] = outfile
            result["message"] = f"Linker report saved to {outfile}"
        else:
            result["report"] = out["stdout"]
            result["message"] = "Linker report generated"
        return result

    def generate_documentation(
        self,
        doc_type: str,
        outfile: Optional[str] = None,
        format: Optional[str] = "html",
        locale: Optional[str] = None,
        timeout: Optional[int] = None,
    ) -> dict[str, Any]:
        """
        Generate documentation (AVM instruction lists).

        Args:
            doc_type: Documentation type: as3.pcode.instructions or
                as12.pcode.instructions
            outfile: Optional output file (stdout when omitted)
            format: Output format (currently only html)
            locale: Optional locale override (e.g. "en")
            timeout: Timeout in seconds

        Returns:
            Result dictionary with the documentation text or file path
        """
        valid_types = {"as3.pcode.instructions", "as12.pcode.instructions"}
        if doc_type not in valid_types:
            raise FFDecError(
                f"Invalid doc type: {doc_type}. Valid: {sorted(valid_types)}"
            )

        args = ["-doc", "-type", doc_type]
        if outfile:
            self._ensure_output_parent(outfile)
            args.extend(["-out", self._normalize_paths(outfile)[0]])
        if format:
            if format != "html":
                raise FFDecError(f"Invalid format: {format}. Valid: html")
            args.extend(["-format", format])
        if locale:
            args.extend(["-locale", locale])

        out = self._run_capture(args, timeout=timeout)
        result: dict[str, Any] = {"success": True, "doc_type": doc_type}
        if outfile:
            result["doc_path"] = outfile
            result["message"] = f"Documentation saved to {outfile}"
        else:
            result["documentation"] = out["stdout"]
            result["message"] = "Documentation generated"
        return result

    # ------------------------------------------------------------------
    # Instance metadata commands
    # ------------------------------------------------------------------

    def get_instance_metadata(
        self,
        swf_path: str,
        instance: str,
        output_format: Optional[str] = None,
        key: Optional[str] = None,
        datafile: Optional[str] = None,
        timeout: Optional[int] = None,
    ) -> dict[str, Any]:
        """
        Read instance metadata from a SWF file.

        Args:
            swf_path: Path to SWF file
            instance: Name of the instance to fetch metadata from
            output_format: Output format (jslike or raw), default jslike
            key: Optional subkey to display
            datafile: Optional file to write the data to
            timeout: Timeout in seconds

        Returns:
            Result dictionary with the metadata text or file path
        """
        is_valid, error = validate_swf_path(swf_path)
        if not is_valid:
            raise FFDecError(error)
        if output_format is not None and output_format not in {"jslike", "raw"}:
            raise FFDecError(
                f"Invalid output format: {output_format}. Valid: jslike, raw"
            )

        swf_norm = self._normalize_paths(swf_path)[0]
        args = ["-getInstanceMetadata", "-instance", instance]
        if output_format:
            args.extend(["-outputFormat", output_format])
        if key:
            args.extend(["-key", key])
        if datafile:
            self._ensure_output_parent(datafile)
            args.extend(["-datafile", self._normalize_paths(datafile)[0]])
        args.append(swf_norm)

        out = self._run_capture(args, timeout=timeout)
        result: dict[str, Any] = {
            "success": True,
            "swf_path": swf_path,
            "instance": instance,
        }
        if datafile:
            result["datafile"] = datafile
            result["message"] = f"Instance metadata written to {datafile}"
        else:
            result["metadata"] = out["stdout"]
            result["message"] = "Instance metadata read"
        return result

    def set_instance_metadata(
        self,
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
        Add or replace instance metadata in a SWF file.

        Args:
            swf_path: Path to SWF file
            instance: Name of the instance to set metadata on
            value: Value to set (when omitted, datafile must be provided)
            datafile: Optional file to read the value from
            key: Optional subkey to set the value under
            input_format: Input format (jslike or raw), default jslike
            outfile: Output SWF path (original file is overwritten when omitted)
            timeout: Timeout in seconds

        Returns:
            Result dictionary with status and details
        """
        is_valid, error = validate_swf_path(swf_path)
        if not is_valid:
            raise FFDecError(error)
        if value is None and datafile is None:
            raise FFDecError("Either value or datafile must be provided")
        if input_format is not None and input_format not in {"jslike", "raw"}:
            raise FFDecError(
                f"Invalid input format: {input_format}. Valid: jslike, raw"
            )

        swf_norm = self._normalize_paths(swf_path)[0]
        args = ["-setInstanceMetadata", "-instance", instance]
        if input_format:
            args.extend(["-inputFormat", input_format])
        if key:
            args.extend(["-key", key])
        if value is not None:
            args.extend(["-value", value])
        if datafile:
            is_valid, error = self._validate_input_file(datafile)
            if not is_valid:
                raise FFDecError(error)
            args.extend(["-datafile", self._normalize_paths(datafile)[0]])
        if outfile:
            self._ensure_output_parent(outfile)
            args.extend(["-outfile", self._normalize_paths(outfile)[0]])
        args.append(swf_norm)

        self._execute(args, timeout=timeout)
        result_path = outfile or swf_path
        return {
            "success": True,
            "swf_path": swf_path,
            "output_path": result_path,
            "instance": instance,
            "message": f"Instance metadata set (output: {result_path})",
        }

    def remove_instance_metadata(
        self,
        swf_path: str,
        instance: str,
        key: Optional[str] = None,
        outfile: Optional[str] = None,
        timeout: Optional[int] = None,
    ) -> dict[str, Any]:
        """
        Remove instance metadata from a SWF file.

        Args:
            swf_path: Path to SWF file
            instance: Name of the instance to remove metadata from
            key: Optional subkey to remove (all metadata when omitted)
            outfile: Output SWF path (original file is overwritten when omitted)
            timeout: Timeout in seconds

        Returns:
            Result dictionary with status and details
        """
        is_valid, error = validate_swf_path(swf_path)
        if not is_valid:
            raise FFDecError(error)

        swf_norm = self._normalize_paths(swf_path)[0]
        args = ["-removeInstanceMetadata", "-instance", instance]
        if key:
            args.extend(["-key", key])
        if outfile:
            self._ensure_output_parent(outfile)
            args.extend(["-outfile", self._normalize_paths(outfile)[0]])
        args.append(swf_norm)

        self._execute(args, timeout=timeout)
        result_path = outfile or swf_path
        return {
            "success": True,
            "swf_path": swf_path,
            "output_path": result_path,
            "instance": instance,
            "message": f"Instance metadata removed (output: {result_path})",
        }

    # ------------------------------------------------------------------
    # Header and compression commands
    # ------------------------------------------------------------------

    def set_header(
        self,
        swf_path: str,
        settings: Optional[dict[str, Any]] = None,
        outfile: Optional[str] = None,
        timeout: Optional[int] = None,
    ) -> dict[str, Any]:
        """
        Print or set SWF header values.

        Args:
            swf_path: Path to SWF file
            settings: Optional dict of header keys to set. Valid keys:
                version, gfx, displayrect, width, height, framecount, framerate.
                When omitted, the current header is printed instead.
            outfile: Output SWF path (required when settings are provided)
            timeout: Timeout in seconds

        Returns:
            Result dictionary with the header values or output path
        """
        is_valid, error = validate_swf_path(swf_path)
        if not is_valid:
            raise FFDecError(error)

        swf_norm = self._normalize_paths(swf_path)[0]
        valid_keys = {
            "version",
            "gfx",
            "displayrect",
            "width",
            "height",
            "framecount",
            "framerate",
        }

        if not settings:
            # Read-only: print current header
            out = self._run_capture(["-header", swf_norm], timeout=timeout)
            metadata = self._parse_header(out["stdout"])
            return {
                "success": True,
                "swf_path": swf_path,
                **metadata,
                "message": "Header read",
            }

        invalid = set(settings) - valid_keys
        if invalid:
            raise FFDecError(
                f"Invalid header keys: {invalid}. Valid: {sorted(valid_keys)}"
            )
        if not outfile:
            raise FFDecError("outfile is required when settings are provided")

        self._ensure_output_parent(outfile)
        out_norm = self._normalize_paths(outfile)[0]
        args = ["-header"]
        for key, value in settings.items():
            args.extend(["-set", key, str(value)])
        args.extend([swf_norm, out_norm])

        self._execute(args, timeout=timeout)
        return {
            "success": True,
            "swf_path": swf_path,
            "output_path": outfile,
            "settings": settings,
            "message": f"Header updated (output: {outfile})",
        }

    def compress_swf(
        self,
        swf_path: str,
        output_path: str,
        action: str = "compress",
        method: Optional[str] = None,
        timeout: Optional[int] = None,
    ) -> dict[str, Any]:
        """
        Compress or decompress a SWF file.

        Note: FFDec v26.x expects the compression method BEFORE the file
        arguments for -compress (despite its help text), so the method is
        always passed (defaulting to zlib).

        Args:
            swf_path: Path to SWF file
            output_path: Path for the resulting SWF file
            action: "compress" or "decompress"
            method: Compression method for compress (zlib or lzma), default zlib
            timeout: Timeout in seconds

        Returns:
            Result dictionary with status and details
        """
        is_valid, error = validate_swf_path(swf_path)
        if not is_valid:
            raise FFDecError(error)
        if action not in {"compress", "decompress"}:
            raise FFDecError(f"Invalid action: {action}. Valid: compress, decompress")
        if action == "compress" and method is not None and method not in {"zlib", "lzma"}:
            raise FFDecError(f"Invalid compression method: {method}. Valid: zlib, lzma")

        self._ensure_output_parent(output_path)
        swf_norm, output_norm = self._normalize_paths(swf_path, output_path)

        if action == "compress":
            args = ["-compress", method or "zlib", swf_norm, output_norm]
        else:
            args = ["-decompress", swf_norm, output_norm]

        self._run_file_to_file(args, output_path, timeout=timeout)
        return {
            "success": True,
            "swf_path": swf_path,
            "output_path": output_path,
            "action": action,
            "message": f"SWF {action}ed successfully (output: {output_path})",
        }

    def encrypt_swf(
        self, swf_path: str, output_path: str, timeout: Optional[int] = None
    ) -> dict[str, Any]:
        """
        Encrypt a SWF file with HARMAN Air encryption.

        Implemented in Python because FFDec 26.4.0's -encrypt CLI command
        incorrectly dispatches to the decrypt parser. The result is verified
        by decrypting it again in memory before writing.

        Args:
            swf_path: Path to SWF file
            output_path: Path for the encrypted SWF file
            timeout: Unused (kept for signature compatibility)

        Returns:
            Result dictionary with status and details
        """
        is_valid, error = validate_swf_path(swf_path)
        if not is_valid:
            raise FFDecError(error)

        data = Path(swf_path).read_bytes()
        if is_encrypted(data):
            raise FFDecError("SWF file is already Air-encrypted")

        try:
            encrypted = harman_encrypt(data)
            if harman_decrypt(encrypted) != data:
                raise ValueError("encrypt/decrypt roundtrip mismatch")
        except ValueError as e:
            raise FFDecExecutionError(f"Air encryption failed: {e}") from e

        self._ensure_output_parent(output_path)
        Path(output_path).write_bytes(encrypted)
        return {
            "success": True,
            "swf_path": swf_path,
            "output_path": output_path,
            "encrypted_size": len(encrypted),
            "message": f"SWF encrypted successfully (output: {output_path})",
        }

    def decrypt_swf(
        self, swf_path: str, output_path: str, timeout: Optional[int] = None
    ) -> dict[str, Any]:
        """
        Decrypt a HARMAN Air encrypted SWF file.

        Implemented in Python (see encrypt_swf). Works identically to FFDec's
        native -decrypt command.

        Args:
            swf_path: Path to the encrypted SWF file
            output_path: Path for the decrypted SWF file
            timeout: Unused (kept for signature compatibility)

        Returns:
            Result dictionary with status and details
        """
        is_valid, error = validate_swf_path(swf_path)
        if not is_valid:
            raise FFDecError(error)

        data = Path(swf_path).read_bytes()
        if not is_encrypted(data):
            raise FFDecError("SWF file is not Air-encrypted")

        try:
            decrypted = harman_decrypt(data)
        except ValueError as e:
            raise FFDecExecutionError(f"Air decryption failed: {e}") from e

        self._ensure_output_parent(output_path)
        Path(output_path).write_bytes(decrypted)
        return {
            "success": True,
            "swf_path": swf_path,
            "output_path": output_path,
            "decrypted_size": len(decrypted),
            "message": f"SWF decrypted successfully (output: {output_path})",
        }

    # ------------------------------------------------------------------
    # Replace / remove commands (SWF editing)
    # ------------------------------------------------------------------

    def replace_asset(
        self,
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
        Replace data of a BinaryData, Image, Shape, Text, Font, Sound tag or Script.

        Args:
            swf_path: Path to SWF file
            output_path: Path for the resulting SWF file
            import_file: File containing the new data
            character_id: Character id of the tag to replace (or use script_name)
            script_name: Script name to replace (for AS3 scripts, instead of id)
            format: Optional format for Image and Shape tags
                (lossless, lossless2, jpeg2, jpeg3, jpeg4)
            method_body_index: Required when the imported entity is AS3 P-code
            nofill: Only valid for shape replace
            start_frame: Sound range start frame (for sound streams)
            timeout: Timeout in seconds

        Returns:
            Result dictionary with status and details
        """
        is_valid, error = validate_swf_path(swf_path)
        if not is_valid:
            raise FFDecError(error)
        if (character_id is None) == (script_name is None):
            raise FFDecError(
                "Provide exactly one of character_id or script_name"
            )
        if format is not None and format not in {
            "lossless",
            "lossless2",
            "jpeg2",
            "jpeg3",
            "jpeg4",
        }:
            raise FFDecError(
                f"Invalid format: {format}. "
                "Valid: lossless, lossless2, jpeg2, jpeg3, jpeg4"
            )

        is_valid, error = self._validate_input_file(import_file)
        if not is_valid:
            raise FFDecError(error)

        self._ensure_output_parent(output_path)
        swf_norm, output_norm, import_norm = self._normalize_paths(
            swf_path, output_path, import_file
        )
        selector = str(character_id) if character_id is not None else script_name

        args = ["-replace", swf_norm, output_norm, selector, import_norm]
        if nofill:
            args.append("nofill")
        if start_frame is not None:
            args.extend(["-startFrame", str(start_frame)])
        if format:
            args.append(format)
        if method_body_index is not None:
            args.append(str(method_body_index))

        self._execute(args, timeout=timeout)
        return {
            "success": True,
            "swf_path": swf_path,
            "output_path": output_path,
            "selector": selector,
            "message": f"Asset replaced successfully (output: {output_path})",
        }

    def replace_alpha(
        self,
        swf_path: str,
        output_path: str,
        pairs: list,
        timeout: Optional[int] = None,
    ) -> dict[str, Any]:
        """
        Replace the alpha channel of JPEG3/JPEG4 image tags.

        Note: the alpha image must have exactly the same dimensions as the
        target JPEG tag.

        Args:
            swf_path: Path to SWF file
            output_path: Path for the resulting SWF file
            pairs: List of [image_id, import_data_file] pairs
            timeout: Timeout in seconds

        Returns:
            Result dictionary with status and details
        """
        is_valid, error = validate_swf_path(swf_path)
        if not is_valid:
            raise FFDecError(error)
        if not pairs:
            raise FFDecError("No image_id/import_file pairs provided")

        normalized_pairs: list[tuple[str, str]] = []
        for pair in pairs:
            if len(pair) != 2:
                raise FFDecError(
                    "Each pair must be [image_id, import_data_file]"
                )
            image_id, import_file = pair
            is_valid, error = self._validate_input_file(import_file)
            if not is_valid:
                raise FFDecError(error)
            normalized_pairs.append((str(image_id), import_file))

        self._ensure_output_parent(output_path)
        swf_norm, output_norm = self._normalize_paths(swf_path, output_path)
        args = ["-replaceAlpha", swf_norm, output_norm]
        for image_id, import_file in normalized_pairs:
            args.extend([image_id, self._normalize_paths(import_file)[0]])

        self._execute(args, timeout=timeout)
        return {
            "success": True,
            "swf_path": swf_path,
            "output_path": output_path,
            "replaced_count": len(normalized_pairs),
            "message": f"Alpha replaced for {len(normalized_pairs)} image(s)",
        }

    def replace_character(
        self,
        swf_path: str,
        output_path: str,
        pairs: list,
        timeout: Optional[int] = None,
    ) -> dict[str, Any]:
        """
        Replace character tags with other characters from the same SWF.

        Args:
            swf_path: Path to SWF file
            output_path: Path for the resulting SWF file
            pairs: List of [character_id, new_character_id] pairs
            timeout: Timeout in seconds

        Returns:
            Result dictionary with status and details
        """
        is_valid, error = validate_swf_path(swf_path)
        if not is_valid:
            raise FFDecError(error)
        if not pairs:
            raise FFDecError("No character_id/new_character_id pairs provided")

        normalized_pairs: list[tuple[str, str]] = []
        for pair in pairs:
            if len(pair) != 2:
                raise FFDecError(
                    "Each pair must be [character_id, new_character_id]"
                )
            normalized_pairs.append((str(pair[0]), str(pair[1])))

        self._ensure_output_parent(output_path)
        swf_norm, output_norm = self._normalize_paths(swf_path, output_path)
        args = ["-replaceCharacter", swf_norm, output_norm]
        for old_id, new_id in normalized_pairs:
            args.extend([old_id, new_id])

        self._execute(args, timeout=timeout)
        return {
            "success": True,
            "swf_path": swf_path,
            "output_path": output_path,
            "replaced_count": len(normalized_pairs),
            "message": f"Replaced {len(normalized_pairs)} character(s)",
        }

    def replace_character_ids(
        self,
        swf_path: str,
        output_path: str,
        pairs: Optional[list] = None,
        mode: Optional[str] = None,
        timeout: Optional[int] = None,
    ) -> dict[str, Any]:
        """
        Replace character ids in bulk, or pack/sort them.

        Args:
            swf_path: Path to SWF file
            output_path: Path for the resulting SWF file
            pairs: List of [old_id, new_id] pairs (used when mode is omitted)
            mode: Bulk operation: "pack" (remove gaps between ids) or
                "sort" (assign increasing ids + pack)
            timeout: Timeout in seconds

        Returns:
            Result dictionary with status and details
        """
        is_valid, error = validate_swf_path(swf_path)
        if not is_valid:
            raise FFDecError(error)
        if mode not in {"pack", "sort"} and not pairs:
            raise FFDecError("Provide pairs or mode (pack/sort)")
        if mode is not None and mode not in {"pack", "sort"}:
            raise FFDecError(f"Invalid mode: {mode}. Valid: pack, sort")

        self._ensure_output_parent(output_path)
        swf_norm, output_norm = self._normalize_paths(swf_path, output_path)

        if mode:
            value = mode
        else:
            for pair in pairs:
                if len(pair) != 2:
                    raise FFDecError("Each pair must be [old_id, new_id]")
            value = ",".join(f"{old},{new}" for old, new in pairs)

        args = ["-replaceCharacterId", swf_norm, output_norm, value]
        self._execute(args, timeout=timeout)
        return {
            "success": True,
            "swf_path": swf_path,
            "output_path": output_path,
            "value": value,
            "message": f"Character ids updated (output: {output_path})",
        }

    def remove_tags(
        self,
        swf_path: str,
        output_path: str,
        tag_indexes: list[int],
        timeout: Optional[int] = None,
    ) -> dict[str, Any]:
        """
        Remove tags (by index on the main timeline) from a SWF file.

        Args:
            swf_path: Path to SWF file
            output_path: Path for the resulting SWF file
            tag_indexes: List of tag indexes to remove
            timeout: Timeout in seconds

        Returns:
            Result dictionary with status and details
        """
        is_valid, error = validate_swf_path(swf_path)
        if not is_valid:
            raise FFDecError(error)
        if not tag_indexes:
            raise FFDecError("No tag indexes provided")

        self._ensure_output_parent(output_path)
        swf_norm, output_norm = self._normalize_paths(swf_path, output_path)
        args = ["-remove", swf_norm, output_norm] + [str(i) for i in tag_indexes]

        self._execute(args, timeout=timeout)
        return {
            "success": True,
            "swf_path": swf_path,
            "output_path": output_path,
            "removed_count": len(tag_indexes),
            "message": f"Removed {len(tag_indexes)} tag(s)",
        }

    def remove_characters(
        self,
        swf_path: str,
        output_path: str,
        character_ids: list[int],
        with_dependencies: bool = False,
        timeout: Optional[int] = None,
    ) -> dict[str, Any]:
        """
        Remove character tags from a SWF file.

        Args:
            swf_path: Path to SWF file
            output_path: Path for the resulting SWF file
            character_ids: List of character ids to remove
            with_dependencies: Also remove dependent characters
            timeout: Timeout in seconds

        Returns:
            Result dictionary with status and details
        """
        is_valid, error = validate_swf_path(swf_path)
        if not is_valid:
            raise FFDecError(error)
        if not character_ids:
            raise FFDecError("No character ids provided")

        self._ensure_output_parent(output_path)
        swf_norm, output_norm = self._normalize_paths(swf_path, output_path)
        command = (
            "-removeCharacterWithDependencies"
            if with_dependencies
            else "-removeCharacter"
        )
        args = [command, swf_norm, output_norm] + [
            str(i) for i in character_ids
        ]

        self._execute(args, timeout=timeout)
        return {
            "success": True,
            "swf_path": swf_path,
            "output_path": output_path,
            "removed_count": len(character_ids),
            "message": f"Removed {len(character_ids)} character(s)",
        }

    # ------------------------------------------------------------------
    # Bulk import commands
    # ------------------------------------------------------------------

    def import_assets(
        self,
        swf_path: str,
        output_path: str,
        asset_type: str,
        folder: str,
        nofill: bool = False,
        timeout: Optional[int] = None,
    ) -> dict[str, Any]:
        """
        Bulk import assets into a SWF file.

        Args:
            swf_path: Path to SWF file
            output_path: Path for the resulting SWF file
            asset_type: One of script, images, sounds, movies, shapes, sprites,
                text, symbolclass
            folder: Folder containing the exported items to import. For
                'symbolclass', the folder must contain a symbols.csv mapping
                file (as produced by exporting the symbolClass asset type)
            nofill: Only valid for shapes import
            timeout: Timeout in seconds

        Returns:
            Result dictionary with status and details
        """
        command_map = {
            "script": "-importScript",
            "images": "-importImages",
            "sounds": "-importSounds",
            "movies": "-importMovies",
            "shapes": "-importShapes",
            "sprites": "-importSprites",
            "text": "-importText",
            "symbolclass": "-importSymbolClass",
        }
        key = asset_type.lower()
        if key not in command_map:
            raise FFDecError(
                f"Invalid asset type: {asset_type}. Valid: {sorted(command_map)}"
            )

        is_valid, error = validate_swf_path(swf_path)
        if not is_valid:
            raise FFDecError(error)

        if key == "symbolclass":
            # FFDec -importSymbolClass expects a folder containing symbols.csv
            is_valid, error = validate_output_dir(folder, create=False)
        else:
            is_valid, error = validate_output_dir(folder, create=False)
        if not is_valid:
            raise FFDecError(error)

        self._ensure_output_parent(output_path)
        swf_norm, output_norm, folder_norm = self._normalize_paths(
            swf_path, output_path, folder
        )
        args = [command_map[key], swf_norm, output_norm]
        if key == "shapes" and nofill:
            args.append("nofill")
        args.append(folder_norm)

        self._execute(args, timeout=timeout)
        return {
            "success": True,
            "swf_path": swf_path,
            "output_path": output_path,
            "asset_type": key,
            "message": f"Assets imported successfully (output: {output_path})",
        }

    # ------------------------------------------------------------------
    # Misc SWF processing commands
    # ------------------------------------------------------------------

    def enable_debugging(
        self,
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
            swf_path: Path to SWF file
            output_path: Path for the resulting SWF file
            inject_as3: Inject debugfile/debugline instructions to match
                decompiled/P-code source
            generate_swd: Generate an SWD file for AS1/AS2 debugging
            pcode: Handle lines as P-code lines (all P-code lines injected)
            timeout: Timeout in seconds

        Returns:
            Result dictionary with status and details
        """
        is_valid, error = validate_swf_path(swf_path)
        if not is_valid:
            raise FFDecError(error)

        self._ensure_output_parent(output_path)
        swf_norm, output_norm = self._normalize_paths(swf_path, output_path)
        args = ["-enabledebugging"]
        if inject_as3:
            args.append("-injectas3")
        if generate_swd:
            args.append("-generateswd")
        if pcode:
            args.append("-pcode")
        args.extend([swf_norm, output_norm])

        self._execute(args, timeout=timeout)
        return {
            "success": True,
            "swf_path": swf_path,
            "output_path": output_path,
            "message": f"Debugging enabled (output: {output_path})",
        }

    def rename_invalid_identifiers(
        self,
        swf_path: str,
        output_path: str,
        mode: str = "typeNumber",
        timeout: Optional[int] = None,
    ) -> dict[str, Any]:
        """
        Rename invalid identifiers in a SWF file.

        Args:
            swf_path: Path to SWF file
            output_path: Path for the resulting SWF file
            mode: Renaming mode: "typeNumber" or "randomWord"
            timeout: Timeout in seconds

        Returns:
            Result dictionary with status and details
        """
        is_valid, error = validate_swf_path(swf_path)
        if not is_valid:
            raise FFDecError(error)
        if mode not in {"typeNumber", "randomWord"}:
            raise FFDecError(
                f"Invalid mode: {mode}. Valid: typeNumber, randomWord"
            )

        self._ensure_output_parent(output_path)
        swf_norm, output_norm = self._normalize_paths(swf_path, output_path)
        self._execute(
            ["-renameInvalidIdentifiers", mode, swf_norm, output_norm],
            timeout=timeout,
        )
        return {
            "success": True,
            "swf_path": swf_path,
            "output_path": output_path,
            "mode": mode,
            "message": f"Invalid identifiers renamed (output: {output_path})",
        }

    # ------------------------------------------------------------------
    # Conversion commands
    # ------------------------------------------------------------------

    def swf_to_xml(
        self,
        swf_path: str,
        output_path: str,
        external: Optional[str] = None,
        timeout: Optional[int] = None,
    ) -> dict[str, Any]:
        """
        Convert a SWF file to XML (full tag-level representation).

        Args:
            swf_path: Path to SWF file
            output_path: Path for the XML file
            external: Optional -external value, comma separated list such as
                "as12script,image,definesound" (or "all")
            timeout: Timeout in seconds

        Returns:
            Result dictionary with status and details
        """
        is_valid, error = validate_swf_path(swf_path)
        if not is_valid:
            raise FFDecError(error)

        self._ensure_output_parent(output_path)
        swf_norm, output_norm = self._normalize_paths(swf_path, output_path)
        args = ["-swf2xml"]
        if external:
            args.extend(["-external", external])
        args.extend([swf_norm, output_norm])

        self._execute(args, timeout=timeout)
        return {
            "success": True,
            "swf_path": swf_path,
            "output_path": output_path,
            "message": f"SWF converted to XML (output: {output_path})",
        }

    def xml_to_swf(
        self, input_path: str, output_path: str, timeout: Optional[int] = None
    ) -> dict[str, Any]:
        """
        Convert an XML file (previously exported by swf_to_xml) back to SWF.

        Args:
            input_path: Path to the XML file
            output_path: Path for the resulting SWF file
            timeout: Timeout in seconds

        Returns:
            Result dictionary with status and details
        """
        is_valid, error = self._validate_input_file(input_path, extensions=[".xml"])
        if not is_valid:
            raise FFDecError(error)

        self._ensure_output_parent(output_path)
        input_norm, output_norm = self._normalize_paths(input_path, output_path)
        self._execute(["-xml2swf", input_norm, output_norm], timeout=timeout)
        return {
            "success": True,
            "input_path": input_path,
            "output_path": output_path,
            "message": f"XML converted to SWF (output: {output_path})",
        }

    def swf_to_exe(
        self,
        swf_path: str,
        output_path: str,
        export_mode: str = "projector_win",
        timeout: Optional[int] = None,
    ) -> dict[str, Any]:
        """
        Export a SWF to an executable file.

        Args:
            swf_path: Path to SWF file
            output_path: Path for the resulting executable
            export_mode: One of wrapper, projector_win, projector_mac,
                projector_linux
            timeout: Timeout in seconds

        Returns:
            Result dictionary with status and details
        """
        valid_modes = {
            "wrapper",
            "projector_win",
            "projector_mac",
            "projector_linux",
        }
        if export_mode not in valid_modes:
            raise FFDecError(
                f"Invalid export mode: {export_mode}. Valid: {sorted(valid_modes)}"
            )

        is_valid, error = validate_swf_path(swf_path)
        if not is_valid:
            raise FFDecError(error)

        self._ensure_output_parent(output_path)
        swf_norm, output_norm = self._normalize_paths(swf_path, output_path)
        self._execute(
            ["-swf2exe", export_mode, output_norm, swf_norm], timeout=timeout
        )
        return {
            "success": True,
            "swf_path": swf_path,
            "output_path": output_path,
            "export_mode": export_mode,
            "message": f"SWF exported to executable (output: {output_path})",
        }

    def swf_to_iggy(
        self,
        swf_path: str,
        output_path: str,
        layout: Optional[str] = None,
        timeout: Optional[int] = None,
    ) -> dict[str, Any]:
        """
        Convert a SWF file to an Iggy file.

        Args:
            swf_path: Path to SWF file
            output_path: Path for the resulting Iggy file
            layout: Optional layout: 32_legacy, 32 or 64 (default)
            timeout: Timeout in seconds

        Returns:
            Result dictionary with status and details
        """
        if layout is not None and layout not in {"32_legacy", "32", "64"}:
            raise FFDecError(
                f"Invalid layout: {layout}. Valid: 32_legacy, 32, 64"
            )

        is_valid, error = validate_swf_path(swf_path)
        if not is_valid:
            raise FFDecError(error)

        self._ensure_output_parent(output_path)
        swf_norm, output_norm = self._normalize_paths(swf_path, output_path)
        args = ["-swf2iggy", swf_norm, output_norm]
        if layout:
            args.append(layout)

        self._execute(args, timeout=timeout)
        return {
            "success": True,
            "swf_path": swf_path,
            "output_path": output_path,
            "layout": layout or "64",
            "message": f"SWF converted to Iggy (output: {output_path})",
        }

    def iggy_to_swf(
        self, input_path: str, output_path: str, timeout: Optional[int] = None
    ) -> dict[str, Any]:
        """
        Convert an Iggy file to a SWF file (layout is detected automatically).

        Args:
            input_path: Path to the Iggy file
            output_path: Path for the resulting SWF file
            timeout: Timeout in seconds

        Returns:
            Result dictionary with status and details
        """
        is_valid, error = self._validate_input_file(input_path)
        if not is_valid:
            raise FFDecError(error)

        self._ensure_output_parent(output_path)
        input_norm, output_norm = self._normalize_paths(input_path, output_path)
        self._execute(["-iggy2swf", input_norm, output_norm], timeout=timeout)
        return {
            "success": True,
            "input_path": input_path,
            "output_path": output_path,
            "message": f"Iggy converted to SWF (output: {output_path})",
        }

    def flashpaper_to_pdf(
        self,
        swf_path: str,
        output_path: str,
        zoom: Optional[int] = None,
        timeout: Optional[int] = None,
    ) -> dict[str, Any]:
        """
        Convert a FlashPaper SWF file to PDF.

        Args:
            swf_path: Path to the FlashPaper SWF file
            output_path: Path for the resulting PDF file
            zoom: Optional zoom level (image quality)
            timeout: Timeout in seconds

        Returns:
            Result dictionary with status and details
        """
        is_valid, error = validate_swf_path(swf_path)
        if not is_valid:
            raise FFDecError(error)

        self._ensure_output_parent(output_path)
        swf_norm, output_norm = self._normalize_paths(swf_path, output_path)
        args: list[str] = []
        if zoom is not None:
            args.extend(["-zoom", str(zoom)])
        args.extend(["-flashpaper2pdf", swf_norm, output_norm])

        self._execute(args, timeout=timeout)
        return {
            "success": True,
            "swf_path": swf_path,
            "output_path": output_path,
            "message": f"FlashPaper converted to PDF (output: {output_path})",
        }

    def swf_to_swc(
        self, swf_path: str, output_path: str, timeout: Optional[int] = None
    ) -> dict[str, Any]:
        """
        Generate a SWC file from a SWF file.

        Args:
            swf_path: Path to SWF file
            output_path: Path for the resulting SWC file
            timeout: Timeout in seconds

        Returns:
            Result dictionary with status and details
        """
        is_valid, error = validate_swf_path(swf_path)
        if not is_valid:
            raise FFDecError(error)

        self._ensure_output_parent(output_path)
        swf_norm, output_norm = self._normalize_paths(swf_path, output_path)
        self._execute(["-swf2swc", output_norm, swf_norm], timeout=timeout)
        return {
            "success": True,
            "swf_path": swf_path,
            "output_path": output_path,
            "message": f"SWC generated (output: {output_path})",
        }

    def merge_abc(
        self, swf_path: str, output_path: str, timeout: Optional[int] = None
    ) -> dict[str, Any]:
        """
        Merge all ABC tags in a SWF file into one.

        Args:
            swf_path: Path to SWF file
            output_path: Path for the merged result file
            timeout: Timeout in seconds

        Returns:
            Result dictionary with status and details
        """
        is_valid, error = validate_swf_path(swf_path)
        if not is_valid:
            raise FFDecError(error)

        self._ensure_output_parent(output_path)
        swf_norm, output_norm = self._normalize_paths(swf_path, output_path)
        self._execute(["-abcmerge", output_norm, swf_norm], timeout=timeout)
        return {
            "success": True,
            "swf_path": swf_path,
            "output_path": output_path,
            "message": f"ABC tags merged (output: {output_path})",
        }

    def clean_abc(
        self, input_path: str, output_path: str, timeout: Optional[int] = None
    ) -> dict[str, Any]:
        """
        Clean an ABC file (or SWF/GFX) by removing all unused items.

        Args:
            input_path: Path to the ABC (.abc) or SWF/GFX file
            output_path: Path for the cleaned result
            timeout: Timeout in seconds

        Returns:
            Result dictionary with status and details
        """
        is_valid, error = self._validate_input_file(input_path)
        if not is_valid:
            raise FFDecError(error)

        self._ensure_output_parent(output_path)
        input_norm, output_norm = self._normalize_paths(input_path, output_path)
        self._execute(["-abcclean", input_norm, output_norm], timeout=timeout)
        return {
            "success": True,
            "input_path": input_path,
            "output_path": output_path,
            "message": f"ABC cleaned (output: {output_path})",
        }

    # ------------------------------------------------------------------
    # Utility commands
    # ------------------------------------------------------------------

    def extract_swf_files(
        self,
        input_path: str,
        output_path: Optional[str] = None,
        mode: Optional[str] = None,
        nocheck: bool = False,
        timeout: Optional[int] = None,
    ) -> dict[str, Any]:
        """
        Extract SWF files from a ZIP or other binary file.

        Args:
            input_path: Path to the ZIP or binary file
            output_path: Output folder path (or file path for biggest/first)
            mode: Extraction mode: all, biggest, smallest, first or last
            nocheck: Skip validation of extracted data
            timeout: Timeout in seconds

        Returns:
            Result dictionary with status and details
        """
        if mode is not None and mode not in {
            "all",
            "biggest",
            "smallest",
            "first",
            "last",
        }:
            raise FFDecError(
                f"Invalid mode: {mode}. Valid: all, biggest, smallest, first, last"
            )

        is_valid, error = self._validate_input_file(input_path)
        if not is_valid:
            raise FFDecError(error)

        input_norm = self._normalize_paths(input_path)[0]
        args = ["-extract", input_norm]
        if output_path:
            if mode in {"biggest", "first"}:
                self._ensure_output_parent(output_path)
            else:
                is_valid, error = validate_output_dir(output_path, create=True)
                if not is_valid:
                    raise FFDecError(error)
            args.extend(["-o", self._normalize_paths(output_path)[0]])
        if nocheck:
            args.append("nocheck")
        if mode:
            args.append(mode)

        self._execute(args, timeout=timeout)
        return {
            "success": True,
            "input_path": input_path,
            "output_path": output_path,
            "mode": mode or "all",
            "message": "SWF extraction completed",
        }

    def search_memory(
        self, processes: list, timeout: Optional[int] = None
    ) -> dict[str, Any]:
        """
        Search SWF files in the memory of running processes.

        Args:
            processes: List of process names or process ids
            timeout: Timeout in seconds

        Returns:
            Result dictionary with the console output
        """
        if not processes:
            raise FFDecError("No process names or ids provided")

        args = ["-memorySearch"] + [str(p) for p in processes]
        out = self._run_capture(args, timeout=timeout, check_returncode=False)
        return {
            "success": True,
            "processes": processes,
            "output": out["stdout"],
            "message": "Memory search completed",
        }

    def run_ffdec(
        self, args: list[str], timeout: Optional[int] = None
    ) -> dict[str, Any]:
        """
        Run FFDec with arbitrary command-line arguments (generic passthrough).

        Args:
            args: FFDec command-line arguments
                (e.g. ["-listconfigs"] or ["-dumpSWF", "/path/file.swf"])
            timeout: Timeout in seconds

        Returns:
            Result dictionary with stdout, stderr and returncode
        """
        if not args:
            raise FFDecError("No arguments provided")

        out = self._run_capture(
            [str(a) for a in args], timeout=timeout, check_returncode=False
        )
        return {
            "success": True,
            "args": args,
            "stdout": out["stdout"],
            "stderr": out["stderr"],
            "returncode": out["returncode"],
            "message": "FFDec executed",
        }

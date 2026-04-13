"""File-type aware extraction helpers for advisory AI analysis."""

from __future__ import annotations

import base64
import hashlib
import io
import mimetypes
import tarfile
import zipfile
from pathlib import Path
from typing import Any, Iterable, Mapping

from sandbox.pe_analyzer import PEHeaderAnalyzer


IMAGE_EXTENSIONS: frozenset[str] = frozenset({
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".bmp",
    ".webp",
    ".tiff",
    ".tif",
})
PDF_EXTENSIONS: frozenset[str] = frozenset({".pdf"})
EXECUTABLE_EXTENSIONS: frozenset[str] = frozenset({".exe", ".dll", ".sys", ".scr", ".com", ".ocx"})
ARCHIVE_EXTENSIONS: frozenset[str] = frozenset({".zip", ".rar", ".7z", ".tar", ".gz", ".bz2", ".xz", ".tgz"})
TEXT_EXTENSIONS: frozenset[str] = frozenset({
    ".txt",
    ".log",
    ".csv",
    ".json",
    ".xml",
    ".yaml",
    ".yml",
    ".ini",
    ".cfg",
    ".md",
    ".py",
    ".ps1",
    ".bat",
    ".cmd",
    ".js",
    ".vbs",
    ".sh",
})
VIDEO_EXTENSIONS: frozenset[str] = frozenset({
    ".mp4",
    ".mov",
    ".avi",
    ".mkv",
    ".wmv",
    ".webm",
    ".m4v",
    ".mpeg",
    ".mpg",
})

INJECTION_PATTERNS: tuple[str, ...] = (
    "ignore previous",
    "ignore all previous",
    "disregard previous",
    "system prompt",
    "developer prompt",
    "you are chatgpt",
    "do not follow",
    "override instruction",
    "act as",
    "jailbreak",
    "reveal hidden",
)


def route_file_type(file_name: str, mime_type: str = "") -> str:
    """Map file name and MIME type into one AI analysis route."""
    suffix = Path(file_name).suffix.lower()
    mime = (mime_type or "").lower().strip()

    if suffix in IMAGE_EXTENSIONS or mime.startswith("image/"):
        return "image"
    if suffix in PDF_EXTENSIONS or mime == "application/pdf":
        return "pdf"
    if suffix in EXECUTABLE_EXTENSIONS:
        return "executable"
    if suffix in VIDEO_EXTENSIONS or mime.startswith("video/"):
        return "video"
    if suffix in ARCHIVE_EXTENSIONS or "zip" in mime or "tar" in mime or "compressed" in mime:
        return "archive"
    if suffix in TEXT_EXTENSIONS or mime.startswith("text/"):
        return "text"
    return "unknown"


class FileIntelligenceExtractor:
    """Build model-safe structured intelligence from scan rows and disk content."""

    def __init__(self) -> None:
        self._pe_analyzer = PEHeaderAnalyzer(simulation_mode=False)

    def build_event_records(
        self,
        rows: Iterable[Mapping[str, Any]],
        *,
        max_files: int,
        max_text_chars: int,
    ) -> list[dict[str, Any]]:
        """Extract analysis records for a bounded number of files."""
        records: list[dict[str, Any]] = []
        for index, row in enumerate(rows):
            if index >= max_files:
                break
            records.append(self.build_file_record(row=row, max_text_chars=max_text_chars))
        return records

    def build_file_record(self, row: Mapping[str, Any], *, max_text_chars: int) -> dict[str, Any]:
        """Extract one normalized file-intelligence record for AI prompts."""
        source = dict(row)

        file_path = self._to_path(source.get("file_path"))
        file_name = str(source.get("file_name") or (file_path.name if file_path else "unknown.bin"))

        mime_type = str(source.get("mime_type") or mimetypes.guess_type(file_name)[0] or "application/octet-stream")
        route = route_file_type(file_name=file_name, mime_type=mime_type)

        size_bytes = self._coerce_int(source.get("size") or source.get("file_size_bytes"), default=0)
        if size_bytes <= 0 and file_path and file_path.exists() and file_path.is_file():
            try:
                size_bytes = int(file_path.stat().st_size)
            except OSError:
                size_bytes = 0

        sha256_hash = self._as_text(source.get("sha256") or source.get("sha256_hash"))
        md5_hash = self._as_text(source.get("md5") or source.get("md5_hash"))
        if file_path and file_path.exists() and (not sha256_hash or not md5_hash):
            computed = self.compute_hashes(file_path)
            sha256_hash = sha256_hash or computed.get("sha256") or ""
            md5_hash = md5_hash or computed.get("md5") or ""

        record: dict[str, Any] = {
            "file_name": file_name,
            "file_path": str(file_path) if file_path else str(source.get("file_path") or file_name),
            "file_type": route,
            "mime_type": mime_type,
            "size_bytes": size_bytes,
            "sha256": sha256_hash,
            "md5": md5_hash,
            "entropy": self._coerce_float(source.get("entropy"), default=0.0),
            "risk_level": str(source.get("risk_level") or source.get("level") or "unknown").lower(),
            "threat_name": self._as_text(source.get("threat_name")),
            "notes": self._as_text(source.get("notes") or source.get("explanation")),
            "scanner_pe": source.get("pe") if isinstance(source.get("pe"), Mapping) else {},
            "scanner_heuristics": source.get("heuristics") if isinstance(source.get("heuristics"), Mapping) else {},
            "feature_vector": source.get("feature_vector") if isinstance(source.get("feature_vector"), Mapping) else {},
            "ml_signals": {
                "level": str(source.get("level") or ""),
                "score": self._coerce_float(source.get("score"), default=0.0),
                "confidence": self._coerce_float(source.get("confidence"), default=0.0),
                "contributions": source.get("contributions") if isinstance(source.get("contributions"), Mapping) else {},
            },
            "content_excerpt": "",
            "content_injection_signals": [],
            "vision_inputs": [],
            "analysis": {},
        }

        if route == "image":
            analysis, images = self._extract_image_analysis(file_path)
            record["analysis"] = analysis
            record["vision_inputs"] = images
        elif route == "pdf":
            analysis, text_excerpt, images = self._extract_pdf_analysis(file_path=file_path, max_text_chars=max_text_chars)
            record["analysis"] = analysis
            record["content_excerpt"] = text_excerpt
            record["vision_inputs"] = images
            record["content_injection_signals"] = detect_prompt_injection(text_excerpt)
        elif route == "executable":
            analysis, excerpt = self._extract_executable_analysis(file_path=file_path, row=source, max_text_chars=max_text_chars)
            record["analysis"] = analysis
            record["content_excerpt"] = excerpt
            record["content_injection_signals"] = detect_prompt_injection(excerpt)
        elif route == "video":
            analysis, images = self._extract_video_analysis(file_path)
            record["analysis"] = analysis
            record["vision_inputs"] = images
        elif route == "archive":
            analysis = self._extract_archive_analysis(file_path=file_path)
            record["analysis"] = analysis
            text_excerpt = self._sanitize_untrusted_text("\n".join(analysis.get("entry_names", [])), max_chars=max_text_chars)
            record["content_excerpt"] = text_excerpt
            record["content_injection_signals"] = detect_prompt_injection(text_excerpt)
        elif route == "text":
            text_excerpt = self._read_text_excerpt(file_path=file_path, max_chars=max_text_chars)
            record["analysis"] = {"encoding": "utf-8-ignore", "readable": bool(text_excerpt)}
            record["content_excerpt"] = text_excerpt
            record["content_injection_signals"] = detect_prompt_injection(text_excerpt)
        else:
            text_excerpt = self._extract_printable_strings(file_path=file_path, max_chars=max_text_chars)
            record["analysis"] = {"readable_strings_found": bool(text_excerpt)}
            record["content_excerpt"] = text_excerpt
            record["content_injection_signals"] = detect_prompt_injection(text_excerpt)

        return record

    def compute_hashes(self, file_path: Path) -> dict[str, str]:
        """Compute file hashes from disk content in bounded chunks."""
        sha256 = hashlib.sha256()
        md5 = hashlib.md5()  # noqa: S324 - compatibility for existing UI/report fields

        try:
            with file_path.open("rb") as stream:
                while True:
                    chunk = stream.read(1024 * 1024)
                    if not chunk:
                        break
                    sha256.update(chunk)
                    md5.update(chunk)
        except OSError:
            return {}

        return {
            "sha256": sha256.hexdigest(),
            "md5": md5.hexdigest(),
        }

    def _extract_image_analysis(self, file_path: Path | None) -> tuple[dict[str, Any], list[dict[str, Any]]]:
        analysis: dict[str, Any] = {
            "format": "unknown",
            "width": None,
            "height": None,
            "mode": None,
            "metadata": {},
        }

        if file_path is None or not file_path.exists() or not file_path.is_file():
            return analysis, []

        images: list[dict[str, Any]] = []

        try:
            from PIL import Image  # type: ignore[import-not-found]

            with Image.open(file_path) as img:
                analysis["format"] = str(img.format or "unknown")
                analysis["width"] = int(img.width)
                analysis["height"] = int(img.height)
                analysis["mode"] = str(img.mode)

                metadata = {}
                info = getattr(img, "info", {}) or {}
                for key, value in info.items():
                    as_text = self._as_text(value)
                    if as_text:
                        metadata[str(key)] = as_text[:120]
                analysis["metadata"] = metadata

                buffer = io.BytesIO()
                thumb = img.copy()
                thumb.thumbnail((1280, 1280))
                thumb.save(buffer, format="PNG")
                images.append(
                    {
                        "label": "image_preview",
                        "mime_type": "image/png",
                        "b64": base64.b64encode(buffer.getvalue()).decode("ascii"),
                    }
                )
        except Exception:
            # PIL may be unavailable; fall back to small raw sample if possible.
            try:
                raw = file_path.read_bytes()
            except OSError:
                raw = b""
            if raw:
                images.append(
                    {
                        "label": "image_raw_sample",
                        "mime_type": "application/octet-stream",
                        "b64": base64.b64encode(raw[: min(len(raw), 180000)]).decode("ascii"),
                    }
                )

        return analysis, images

    def _extract_pdf_analysis(
        self,
        *,
        file_path: Path | None,
        max_text_chars: int,
    ) -> tuple[dict[str, Any], str, list[dict[str, Any]]]:
        analysis: dict[str, Any] = {
            "page_count": 0,
            "metadata": {},
            "is_image_heavy": False,
            "text_extraction_mode": "none",
        }
        text_excerpt = ""
        images: list[dict[str, Any]] = []

        if file_path is None or not file_path.exists() or not file_path.is_file():
            return analysis, text_excerpt, images

        try:
            import fitz  # type: ignore[import-not-found]

            doc = fitz.open(file_path)
            analysis["page_count"] = int(doc.page_count)
            analysis["metadata"] = {
                str(k): self._as_text(v)[:120]
                for k, v in dict(doc.metadata or {}).items()
                if self._as_text(v)
            }

            snippets: list[str] = []
            image_pages = 0
            for idx in range(min(5, doc.page_count)):
                page = doc[idx]
                page_text = self._sanitize_untrusted_text(page.get_text("text"), max_chars=max_text_chars)
                if page_text:
                    snippets.append(page_text)
                if page.get_images(full=True):
                    image_pages += 1

            text_excerpt = self._sanitize_untrusted_text("\n".join(snippets), max_chars=max_text_chars)
            is_image_heavy = (image_pages >= max(1, min(2, doc.page_count))) or (len(text_excerpt) < 120)
            analysis["is_image_heavy"] = bool(is_image_heavy)
            analysis["text_extraction_mode"] = "pymupdf"

            if is_image_heavy and doc.page_count > 0:
                for idx in range(min(2, doc.page_count)):
                    pix = doc[idx].get_pixmap(matrix=fitz.Matrix(1.35, 1.35), alpha=False)
                    images.append(
                        {
                            "label": f"pdf_page_{idx+1}",
                            "mime_type": "image/png",
                            "b64": base64.b64encode(pix.tobytes("png")).decode("ascii"),
                        }
                    )
            doc.close()
        except Exception:
            text_excerpt = self._extract_printable_strings(file_path=file_path, max_chars=max_text_chars)
            analysis["text_extraction_mode"] = "printable_strings"

        return analysis, text_excerpt, images

    def _extract_executable_analysis(
        self,
        *,
        file_path: Path | None,
        row: Mapping[str, Any],
        max_text_chars: int,
    ) -> tuple[dict[str, Any], str]:
        pe_row = row.get("pe") if isinstance(row.get("pe"), Mapping) else {}
        pe_info = dict(pe_row)

        if not pe_info and file_path and file_path.exists() and file_path.is_file():
            pe_info = self._pe_analyzer.analyze_file(file_path)

        extended = self._extract_executable_extended(file_path)
        analysis = {
            "pe": pe_info,
            "extended": extended,
            "imports_count": len(pe_info.get("imports", [])) if isinstance(pe_info.get("imports"), list) else 0,
            "suspicious_api_count": len(pe_info.get("suspicious_apis", [])) if isinstance(pe_info.get("suspicious_apis"), list) else 0,
            "threat_indicators": pe_info.get("threat_indicators", []),
        }

        strings_excerpt = self._extract_printable_strings(file_path=file_path, max_chars=max_text_chars)
        return analysis, strings_excerpt

    def _extract_executable_extended(self, file_path: Path | None) -> dict[str, Any]:
        if file_path is None or not file_path.exists() or not file_path.is_file():
            return {}

        try:
            import pefile  # type: ignore[import-not-found]

            pe = pefile.PE(str(file_path), fast_load=True)
            sections: list[dict[str, Any]] = []
            for section in getattr(pe, "sections", [])[:10]:
                try:
                    sections.append(
                        {
                            "name": section.Name.decode(errors="ignore").strip("\x00"),
                            "virtual_size": int(section.Misc_VirtualSize),
                            "raw_size": int(section.SizeOfRawData),
                            "entropy": round(float(section.get_entropy()), 4),
                        }
                    )
                except Exception:
                    continue

            timestamp = None
            try:
                timestamp = int(pe.FILE_HEADER.TimeDateStamp)
            except Exception:
                timestamp = None

            return {
                "machine": int(getattr(pe.FILE_HEADER, "Machine", 0)),
                "number_of_sections": int(getattr(pe.FILE_HEADER, "NumberOfSections", 0)),
                "timestamp": timestamp,
                "sections": sections,
            }
        except Exception:
            return {}

    def _extract_video_analysis(self, file_path: Path | None) -> tuple[dict[str, Any], list[dict[str, Any]]]:
        analysis: dict[str, Any] = {
            "duration_seconds": None,
            "fps": None,
            "frame_count": None,
            "width": None,
            "height": None,
            "key_frame_strategy": "none",
        }
        frames: list[dict[str, Any]] = []

        if file_path is None or not file_path.exists() or not file_path.is_file():
            return analysis, frames

        try:
            import cv2  # type: ignore[import-not-found]

            capture = cv2.VideoCapture(str(file_path))
            if not capture.isOpened():
                return analysis, frames

            frame_count = int(capture.get(cv2.CAP_PROP_FRAME_COUNT) or 0)
            fps = float(capture.get(cv2.CAP_PROP_FPS) or 0.0)
            width = int(capture.get(cv2.CAP_PROP_FRAME_WIDTH) or 0)
            height = int(capture.get(cv2.CAP_PROP_FRAME_HEIGHT) or 0)
            duration = float(frame_count / fps) if fps > 0 else None

            analysis.update(
                {
                    "duration_seconds": round(duration, 3) if duration is not None else None,
                    "fps": round(fps, 3) if fps > 0 else None,
                    "frame_count": frame_count,
                    "width": width,
                    "height": height,
                    "key_frame_strategy": "start_mid_end",
                }
            )

            indices = sorted({0, max(0, frame_count // 2), max(0, frame_count - 1)})
            for idx in indices:
                capture.set(cv2.CAP_PROP_POS_FRAMES, idx)
                success, frame = capture.read()
                if not success:
                    continue
                ok, encoded = cv2.imencode(".jpg", frame)
                if not ok:
                    continue
                frames.append(
                    {
                        "label": f"video_frame_{idx}",
                        "mime_type": "image/jpeg",
                        "b64": base64.b64encode(encoded.tobytes()).decode("ascii"),
                    }
                )

            capture.release()
        except Exception:
            analysis["key_frame_strategy"] = "opencv_unavailable"

        return analysis, frames

    def _extract_archive_analysis(self, *, file_path: Path | None) -> dict[str, Any]:
        analysis: dict[str, Any] = {
            "entry_count": 0,
            "entry_names": [],
            "contains_nested_archives": False,
            "contains_executable_names": False,
            "enumeration_mode": "none",
            "truncated": False,
        }

        if file_path is None or not file_path.exists() or not file_path.is_file():
            return analysis

        names: list[str] = []
        max_entries = 200

        try:
            if zipfile.is_zipfile(file_path):
                with zipfile.ZipFile(file_path, "r") as zf:
                    for info in zf.infolist():
                        if len(names) >= max_entries:
                            analysis["truncated"] = True
                            break
                        names.append(info.filename)
                analysis["enumeration_mode"] = "zip"
            elif tarfile.is_tarfile(file_path):
                with tarfile.open(file_path, "r:*") as tf:
                    for member in tf.getmembers():
                        if len(names) >= max_entries:
                            analysis["truncated"] = True
                            break
                        names.append(member.name)
                analysis["enumeration_mode"] = "tar"
            else:
                analysis["enumeration_mode"] = "unsupported"
        except Exception:
            analysis["enumeration_mode"] = "error"

        normalized = [str(name).replace("\\", "/") for name in names]
        analysis["entry_count"] = len(normalized)
        analysis["entry_names"] = normalized[:80]
        analysis["contains_nested_archives"] = any(Path(n).suffix.lower() in ARCHIVE_EXTENSIONS for n in normalized)
        analysis["contains_executable_names"] = any(Path(n).suffix.lower() in EXECUTABLE_EXTENSIONS for n in normalized)
        return analysis

    def _read_text_excerpt(self, *, file_path: Path | None, max_chars: int) -> str:
        if file_path is None or not file_path.exists() or not file_path.is_file():
            return ""

        try:
            data = file_path.read_bytes()
        except OSError:
            return ""

        # Avoid treating binary blobs as text content.
        if b"\x00" in data[:4096]:
            return ""

        text = data.decode("utf-8", errors="ignore")
        return self._sanitize_untrusted_text(text, max_chars=max_chars)

    def _extract_printable_strings(self, *, file_path: Path | None, max_chars: int) -> str:
        if file_path is None or not file_path.exists() or not file_path.is_file():
            return ""

        try:
            sample = file_path.read_bytes()[: min(256000, max_chars * 6)]
        except OSError:
            return ""

        chunks: list[str] = []
        current: list[str] = []
        for raw in sample:
            if 32 <= raw <= 126:
                current.append(chr(raw))
            else:
                if len(current) >= 5:
                    chunks.append("".join(current))
                current = []
        if len(current) >= 5:
            chunks.append("".join(current))

        joined = "\n".join(chunks[:160])
        return self._sanitize_untrusted_text(joined, max_chars=max_chars)

    def _sanitize_untrusted_text(self, value: str, *, max_chars: int) -> str:
        if not value:
            return ""
        cleaned = "".join(ch for ch in value if ch.isprintable() or ch in "\n\r\t")
        cleaned = cleaned.replace("\r\n", "\n").replace("\r", "\n")
        if len(cleaned) > max_chars:
            cleaned = cleaned[:max_chars]
        return cleaned.strip()

    def _to_path(self, value: Any) -> Path | None:
        if value is None:
            return None
        text = str(value).strip()
        if not text:
            return None
        try:
            return Path(text)
        except (TypeError, ValueError, OSError):
            return None

    def _coerce_float(self, value: Any, *, default: float) -> float:
        try:
            return float(value)
        except (TypeError, ValueError):
            return default

    def _coerce_int(self, value: Any, *, default: int) -> int:
        try:
            return int(value)
        except (TypeError, ValueError):
            return default

    def _as_text(self, value: Any) -> str:
        if value is None:
            return ""
        text = str(value).strip()
        return text


def detect_prompt_injection(text: str) -> list[str]:
    """Return known prompt-injection indicators found in untrusted text."""
    lowered = (text or "").lower()
    hits = [pattern for pattern in INJECTION_PATTERNS if pattern in lowered]
    return hits

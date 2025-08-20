#!/usr/bin/env python3
"""
Flask server for AI Image Forensic Analyzer

Features:
- ExifTool integration for comprehensive metadata analysis.
- Hexdump integration for low-level binary artifact detection.
- High-confidence prediction (100%) on AI keyword match.
- Weighted scoring for multiple forensic indicators.
- Structured JSON response for easy frontend integration.
- Security hardening with magic number validation and security headers.
- Performance optimization with in-memory caching.
"""

import os
import io
import json
import base64
import logging
import tempfile
import subprocess
import hashlib
from typing import List, Optional, Tuple, Dict
from dataclasses import dataclass
from pathlib import Path
from datetime import datetime, timezone
from collections import OrderedDict

from flask import Flask, request, jsonify, render_template
from werkzeug.utils import secure_filename

import numpy as np
import cv2
from PIL import Image, ImageChops, ImageEnhance
from PIL.ExifTags import TAGS

# -----------------------------
# Flask / App configuration
# -----------------------------
TEMPLATES_DIR = 'templates'
STATIC_DIR = 'static'

app = Flask(__name__, template_folder=TEMPLATES_DIR, static_folder=STATIC_DIR)
UPLOAD_FOLDER = Path(tempfile.gettempdir()) / "Metadata_uploads"
UPLOAD_FOLDER.mkdir(exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 10 * 1024 * 1024 # Increased to 10MB
ALLOWED_EXTENSIONS = {"jpg", "jpeg", "png", "webp", "bmp", "tif", "tiff", "gif"}
np.set_printoptions(suppress=True)

# -----------------------------
# Logging
# -----------------------------
LOG_DIR = Path(tempfile.gettempdir()) / "Metadata_logs"
LOG_DIR.mkdir(exist_ok=True)
LOG_FILE = LOG_DIR / "forensics.log"
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[logging.FileHandler(LOG_FILE), logging.StreamHandler()],
)
logger = logging.getLogger("MetadataAnalyzer")

# -----------------------------
# Caching Setup (Performance Optimization)
# -----------------------------
CACHE_MAX_SIZE = 100
analysis_cache = OrderedDict()

# -----------------------------
# Config
# -----------------------------
@dataclass
class Config:
    EXIFTOOL_PATH: Path = Path("/usr/bin/exiftool") # Path to your exiftool executable
    HEXDUMP_PATH: Path = Path("/usr/bin/hexdump") # Path to your hexdump executable
    MIN_IMAGE_SIZE: int = 64
    AI_GENERATOR_KEYWORDS: List[str] = None
    CAMERA_KEYWORDS: List[str] = None
    THRESHOLDS: dict = None
    RETURN_VISUALS: bool = False # Set to False to speed up response

    def __post_init__(self):
        if self.AI_GENERATOR_KEYWORDS is None:
            self.AI_GENERATOR_KEYWORDS = [
                "midjourney", "dall-e", "dall e", "dall·e", "stable diffusion",
                "copilot", "bing image creator", "adobe firefly", "firefly",
                "leonardo.ai", "leonardo ai", "nightcafe", "wombo dream",
                "craiyon", "playground ai", "artbreeder", "starryai",
                "deepai", "imagen", "stylegan", "gaugan", "nvidia",
                "stability ai", "openai", "aigenerated", "azure openai"
            ]
        if self.CAMERA_KEYWORDS is None:
            self.CAMERA_KEYWORDS = ["canon", "nikon", "sony", "fujifilm", "panasonic", "olympus", "leica", "apple", "google", "samsung"]
        if self.THRESHOLDS is None:
            self.THRESHOLDS = {
                "FFT_AI_THRESHOLD": 0.12,
                "FFT_REAL_THRESHOLD": 0.17,
                "NOISE_STD_DEV_AI_THRESHOLD": 80.0,
                "ELA_AI_THRESHOLD": 25.0,
                "BLOCK_BOUNDARY_AI_THRESHOLD": 6.0,
                "SAT_MEAN_HIGH": 110.0,
                "SAT_STD_HIGH": 60.0,
            }

config = Config()

# -----------------------------
# Security Helpers
# -----------------------------
def is_valid_image_file(file_stream: io.BytesIO, filename: str) -> bool:
    """
    SECURITY HARDENING: Validates a file by checking its extension AND its magic numbers.
    This prevents spoofing file extensions.
    """
    extension = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
    if extension not in ALLOWED_EXTENSIONS:
        return False

    magic_numbers = {
        b"\xff\xd8\xff": "jpeg",
        b"\x89PNG\r\n\x1a\n": "png",
        b"GIF8": "gif",
        b"BM": "bmp",
        b"RIFF": "webp",
        b"II*\x00": "tiff",
        b"MM\x00*": "tiff",
    }
    
    header = file_stream.read(12)
    file_stream.seek(0) # IMPORTANT: Rewind the stream for later use

    for magic in magic_numbers:
        if header.startswith(magic):
            return True
            
    return False

def pil_from_stream(stream: io.BytesIO) -> Optional[Image.Image]:
    """Helper to load a PIL Image from an in-memory stream."""
    try:
        stream.seek(0)
        with Image.open(stream) as im:
            im.load()
            return im.convert("RGB")
    except Exception as e:
        logger.error(f"Failed to load image with Pillow from stream: {e}")
        return None

# -----------------------------
# General Helpers
# -----------------------------
def normalize_to_uint8(x: np.ndarray) -> np.ndarray:
    x = x.astype(np.float32)
    mn, mx = np.nanmin(x), np.nanmax(x)
    if mx <= mn: return np.zeros_like(x, dtype=np.uint8)
    y = (x - mn) / (mx - mn)
    return (y * 255).clip(0, 255).astype(np.uint8)

def to_base64_png_from_array(arr: np.ndarray) -> str:
    im = Image.fromarray(normalize_to_uint8(arr), mode="L")
    buf = io.BytesIO()
    im.save(buf, format="PNG")
    return base64.b64encode(buf.getvalue()).decode("ascii")

# -----------------------------
# Analyzers
# -----------------------------
class MetadataAnalyzer:
    def __init__(self, exiftool_path: Path, ai_keywords: List[str]):
        self.exiftool_path = exiftool_path
        self.ai_keywords = ai_keywords
        self.real_fields = ["Make", "Model", "LensModel", "DateTimeOriginal"]

    def analyze(self, path: Path) -> Dict:
        results = {"Metadata_Hits": "", "Camera_Info": ""}
        try:
            process = subprocess.run(
                [str(self.exiftool_path), '-j', '-G', str(path)],
                capture_output=True, text=True, check=True, encoding="utf-8", errors="replace"
            )
            metadata_list = json.loads(process.stdout)
            if not metadata_list: return results
            metadata = metadata_list[0]

            found_hits = set()
            for key, value in metadata.items():
                val_str = str(value).lower()
                for kw in self.ai_keywords:
                    if kw in val_str:
                        found_hits.add(kw.capitalize())
            
            if found_hits:
                results["Metadata_Hits"] = ", ".join(sorted(list(found_hits)))

            camera_info = []
            for field in self.real_fields:
                for group_field in [f"EXIF:{field}", f"Composite:{field}"]:
                    if group_field in metadata:
                        camera_info.append(f"{field}: {metadata[group_field]}")
                        break
            
            if camera_info:
                results["Camera_Info"] = "; ".join(camera_info)

        except Exception as e:
            logger.warning(f"ExifTool analysis failed for {path.name}: {e}")
            results["Metadata_Hits"] = "Metadata Read Error"
        
        return results

class HexdumpAnalyzer:
    def __init__(self, hexdump_path: Path, ai_keywords: List[str], camera_keywords: List[str]):
        self.hexdump_path = hexdump_path
        self.ai_keywords = [kw.encode('ascii', 'ignore') for kw in ai_keywords]
        self.camera_keywords = [kw.encode('ascii', 'ignore') for kw in camera_keywords]

    def analyze(self, path: Path) -> Dict:
        results = {
            "Hex_Found_AI_Strings": "",
            "Hex_Found_Camera_Strings": "",
            "Hex_Found_PNG_tEXt": False,
        }
        try:
            # Read the first 4KB of the file for efficient analysis
            with open(path, "rb") as f:
                content = f.read(4096)

            # Check for AI keywords
            found_ai = set()
            for kw in self.ai_keywords:
                if kw in content.lower():
                    found_ai.add(kw.decode('ascii'))
            if found_ai:
                 results["Hex_Found_AI_Strings"] = ", ".join(sorted(list(found_ai)))

            # Check for Camera keywords
            found_camera = set()
            for kw in self.camera_keywords:
                if kw in content.lower():
                    found_camera.add(kw.decode('ascii'))
            if found_camera:
                results["Hex_Found_Camera_Strings"] = ", ".join(sorted(list(found_camera)))
            
            # Check for the specific PNG 'tEXt' chunk used by A1111
            if b'tEXt' in content:
                results["Hex_Found_PNG_tEXt"] = True

        except Exception as e:
            logger.warning(f"Hexdump analysis failed for {path.name}: {e}")
        return results

class FrequencyAnalyzer:
    @staticmethod
    def analyze(path: Path) -> Dict:
        try:
            img = cv2.imread(str(path), cv2.IMREAD_GRAYSCALE)
            if img is None: return {"FFT_Score": None, "FFT_Visual": ""}
            f = np.fft.fft2(img)
            fshift = np.fft.fftshift(f)
            mag = 20 * np.log(np.abs(fshift) + 1.0)
            score = float(np.std(mag) / (np.mean(mag) + 1e-6))
            vis = to_base64_png_from_array(mag) if config.RETURN_VISUALS else ""
            return {"FFT_Score": score, "FFT_Visual": vis}
        except Exception:
            return {"FFT_Score": None, "FFT_Visual": ""}

class NoiseAnalyzer:
    @staticmethod
    def analyze(pil_img: Image.Image) -> Dict:
        try:
            gray = np.array(pil_img.convert("L"), dtype=np.float32)
            blurred = cv2.GaussianBlur(gray, (5, 5), 1.0)
            noise = gray - blurred
            std = float(np.std(noise))
            vis = to_base64_png_from_array(np.abs(noise)) if config.RETURN_VISUALS else ""
            return {"Noise_StdDev": std, "Noise_Visual": vis}
        except Exception:
            return {"Noise_StdDev": None, "Noise_Visual": ""}

class ELAAnalyzer:
    @staticmethod
    def analyze(pil_img: Image.Image, quality: int = 90) -> Dict:
        try:
            buf = io.BytesIO()
            pil_img.save(buf, "JPEG", quality=quality)
            buf.seek(0)
            recompressed = Image.open(buf).convert("RGB")
            ela = ImageChops.difference(pil_img, recompressed)
            ela_enhanced = ImageEnhance.Brightness(ela).enhance(2.0)
            extrema = ela.getextrema()
            max_diff = max([ex[1] for ex in extrema if ex])
            ela_arr = np.array(ela_enhanced)
            vis = to_base64_png_from_array(ela_arr) if config.RETURN_VISUALS else ""
            return {"ELA_MaxDiff": float(max_diff), "ELA_Visual": vis}
        except Exception:
            return {"ELA_MaxDiff": None, "ELA_Visual": ""}

class ColorStatsAnalyzer:
    @staticmethod
    def analyze(pil_img: Image.Image) -> Dict:
        try:
            rgb = np.array(pil_img.convert("RGB"))
            hsv = cv2.cvtColor(rgb, cv2.COLOR_RGB2HSV)
            h, s, v = cv2.split(hsv)
            return {
                "Sat_Mean": float(np.mean(s)),
                "Sat_Std": float(np.std(s)),
                "Brightness_Mean": float(np.mean(v)),
                "Brightness_Std": float(np.std(v)),
            }
        except Exception:
            return {"Sat_Mean": None, "Sat_Std": None, "Brightness_Mean": None, "Brightness_Std": None}

class BlockArtifactAnalyzer:
    @staticmethod
    def analyze(pil_img: Image.Image, block: int = 8) -> Dict:
        try:
            gray = np.array(pil_img.convert("L"), dtype=np.float32)
            vert_edges, horiz_edges = [], []
            for x in range(block, gray.shape[1], block):
                if x < gray.shape[1]: vert_edges.append(np.abs(gray[:, x] - gray[:, x - 1]))
            for y in range(block, gray.shape[0], block):
                if y < gray.shape[0]: horiz_edges.append(np.abs(gray[y, :] - gray[y - 1, :]))
            if not vert_edges and not horiz_edges: return {"Block_Boundary_Energy": None}
            v_energy = np.mean(vert_edges) if vert_edges else 0.0
            h_energy = np.mean(horiz_edges) if horiz_edges else 0.0
            return {"Block_Boundary_Energy": float((v_energy + h_energy) / 2.0)}
        except Exception:
            return {"Block_Boundary_Energy": None}

# -----------------------------
# Forensic pipeline
# -----------------------------
class ForensicImageAnalyzer:
    def __init__(self, cfg: Config):
        self.cfg = cfg
        self.meta = MetadataAnalyzer(cfg.EXIFTOOL_PATH, cfg.AI_GENERATOR_KEYWORDS)
        self.hexdump = HexdumpAnalyzer(cfg.HEXDUMP_PATH, cfg.AI_GENERATOR_KEYWORDS, cfg.CAMERA_KEYWORDS)
        self.freq = FrequencyAnalyzer()
        self.noise = NoiseAnalyzer()
        self.ela = ELAAnalyzer()
        self.color = ColorStatsAnalyzer()
        self.blocks = BlockArtifactAnalyzer()

    def process(self, path: Path, file_stream: io.BytesIO) -> Optional[Dict]:
        """
        PERFORMANCE OPTIMIZATION: Now accepts an in-memory stream to reduce disk reads.
        """
        pil_img = pil_from_stream(file_stream)
        if not pil_img or min(pil_img.size) < self.cfg.MIN_IMAGE_SIZE:
            return None

        results = {"FileName": path.name}
        
        # Analyzers needing a file path (for external tools)
        results.update(self.meta.analyze(path))
        results.update(self.hexdump.analyze(path))
        results.update(self.freq.analyze(path))
        
        # Analyzers using the in-memory PIL image
        results.update(self.noise.analyze(pil_img))
        results.update(self.ela.analyze(pil_img))
        results.update(self.color.analyze(pil_img))
        results.update(self.blocks.analyze(pil_img))

        # Compute final prediction using the unified scoring function
        pred = self._predict_unified(results)
        results.update(pred)

        return results

    def _predict_unified(self, r: Dict) -> Dict:
        """A precise, unified function to calculate AI probability."""
        
        # --- Rule 1: High-Confidence AI Detection (100% Probability) ---
        if r.get("Metadata_Hits") and "Error" not in r["Metadata_Hits"]:
            return {
                "AI_Probability_Score": 1.0,
                "Prediction": "AI-Generated",
                "Confidence": "Very High",
                "Reasoning": f"Definitive AI keyword found in metadata: {r['Metadata_Hits']}",
            }

        # --- If no definitive keywords, proceed with weighted scoring ---
        score = 0.0
        reasons = []

        # --- UPDATED SCORING LOGIC ---
        # 2) Hex-based strings (strong indicators)
        if r.get("Hex_Found_AI_Strings"):
            score += 0.8
            reasons.append(f"AI-related string found in file binary: {r['Hex_Found_AI_Strings']}")
        
        if r.get("Hex_Found_Camera_Strings"):
            score -= 0.4
            reasons.append(f"Camera-related string found in file binary: {r['Hex_Found_Camera_Strings']}")

        # 3) Camera metadata info (strong negative weight)
        if r.get("Camera_Info"):
            score -= 0.45
            reasons.append(f"Strong evidence of authenticity from camera metadata ({r['Camera_Info']})")

        # 4) FFT score (lower is more suspicious)
        fft = r.get("FFT_Score")
        if fft is not None:
            if fft < self.cfg.THRESHOLDS["FFT_AI_THRESHOLD"]:
                score += 0.25
                reasons.append(f"FFT score low ({fft:.3f}) — AI-like uniformity")
            elif fft > self.cfg.THRESHOLDS["FFT_REAL_THRESHOLD"]:
                score -= 0.2
                reasons.append(f"FFT score high ({fft:.3f}) — natural variance")

        # 5) Noise residual std dev (higher can be suspicious for some models)
        nstd = r.get("Noise_StdDev")
        if nstd is not None and nstd > self.cfg.THRESHOLDS["NOISE_STD_DEV_AI_THRESHOLD"]:
            score += 0.25
            reasons.append(f"Noise std dev high ({nstd:.2f})")
            
        # 6) ELA max diff (higher is suspicious)
        ela = r.get("ELA_MaxDiff")
        if ela is not None and ela > self.cfg.THRESHOLDS["ELA_AI_THRESHOLD"]:
            score += 0.25
            reasons.append(f"ELA artifacts strong (max diff {ela:.1f})")

        # 7) JPEG block boundary energy (higher is suspicious)
        bbe = r.get("Block_Boundary_Energy")
        if bbe is not None and bbe > self.cfg.THRESHOLDS["BLOCK_BOUNDARY_AI_THRESHOLD"]:
            score += 0.2
            reasons.append(f"Pronounced 8×8 block boundaries ({bbe:.2f})")
            
        # 8) PNG tEXt chunk (corroborating evidence for some generators)
        if r.get("Hex_Found_PNG_tEXt"):
            score += 0.15
            reasons.append("PNG 'tEXt' chunk found, often used by AI tools to store parameters.")

        # 9) Saturation stats (very vivid & varied saturation can be suspicious)
        sm, ss = r.get("Sat_Mean"), r.get("Sat_Std")
        if sm is not None and ss is not None:
            sat_flags = []
            if sm > self.cfg.THRESHOLDS["SAT_MEAN_HIGH"]: sat_flags.append(f"mean {sm:.1f}")
            if ss > self.cfg.THRESHOLDS["SAT_STD_HIGH"]: sat_flags.append(f"std {ss:.1f}")
            if sat_flags:
                score += 0.1
                reasons.append("High saturation (" + ", ".join(sat_flags) + ")")
        # --- END OF UPDATED SCORING LOGIC ---

        # Clamp score between 0.0 and 1.0 and classify
        score = float(min(1.0, max(0.0, score)))

        if score > 0.70:
            prediction, confidence = "AI-Generated", "High"
        elif score > 0.45:
            prediction, confidence = "Potentially AI", "Medium"
        else:
            prediction, confidence = "Likely Real", "High" if score < 0.30 else "Medium"

        if not reasons:
            reasons.append("No strong forensic indicators found.")

        return {
            "AI_Probability_Score": score,
            "Prediction": prediction,
            "Confidence": confidence,
            "Reasoning": " | ".join(reasons),
        }

# -----------------------------
# Routes
# -----------------------------
@app.after_request
def add_security_headers(response):
    """SECURITY HARDENING: Adds security headers to every response."""
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Content-Security-Policy'] = "default-src 'self'"
    return response

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/analyze", methods=["POST"])
def analyze_image():
    if "file" not in request.files:
        return jsonify({"error": "No file part"}), 400
    file = request.files["file"]
    
    if file.filename == "":
        return jsonify({"error": "No file selected"}), 400

    # --- UPDATED LOGIC FOR SECURITY AND PERFORMANCE ---
    file_stream = io.BytesIO(file.read())
    file.close()

    if not is_valid_image_file(file_stream, file.filename):
        return jsonify({"error": "Invalid or unsupported image file type."}), 415

    file_hash = hashlib.sha256(file_stream.getvalue()).hexdigest()
    if file_hash in analysis_cache:
        logger.info(f"Serving result for {secure_filename(file.filename)} (hash: {file_hash[:10]}...) from cache.")
        return jsonify(analysis_cache[file_hash]), 200

    temp_path = UPLOAD_FOLDER / secure_filename(file.filename)
    try:
        with open(temp_path, "wb") as f:
            f.write(file_stream.getvalue())

        analyzer = ForensicImageAnalyzer(config)
        result = analyzer.process(temp_path, file_stream) 
        
        if not result:
            return jsonify({"error": "Analysis failed. Image may be corrupted or too small."}), 422

        analysis_cache[file_hash] = result
        if len(analysis_cache) > CACHE_MAX_SIZE:
            analysis_cache.popitem(last=False)

        return jsonify(result), 200
        
    except Exception:
        logger.exception("Analysis error")
        return jsonify({"error": "An internal server error occurred."}), 500
    finally:
        # AUTOMATED CLEANUP
        if temp_path.exists():
            temp_path.unlink()

# -----------------------------
# Main
# -----------------------------
if __name__ == "__main__":
    if not config.EXIFTOOL_PATH.exists():
        logger.error(f"FATAL: ExifTool not found at '{config.EXIFTOOL_PATH}'. Please install it or update the path.")
    elif not config.HEXDUMP_PATH.exists():
         logger.error(f"FATAL: hexdump not found at '{config.HEXDUMP_PATH}'. Please install it or update the path.")
    else:
        logger.info("Starting AI Image Forensic Analyzer Flask server with security and performance enhancements.")
        app.run(debug=False, host='0.0.0.0', port=5000)
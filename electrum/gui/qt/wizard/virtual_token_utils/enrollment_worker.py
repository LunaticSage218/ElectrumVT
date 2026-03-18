from __future__ import annotations

import shutil
import time
import traceback
from pathlib import Path
from typing import Optional, Dict, Any

from PyQt6.QtCore import QObject, pyqtSignal

from electrum.gui.qt.wizard.virtual_token_utils.enrollment_protocol import enrollment_protocol

from electrum.gui.qt.wizard.virtual_token_utils.utils import secure_filename
from electrum.gui.qt.wizard.virtual_token_utils.paths import UPLOAD_DIR

class EnrollmentWorker(QObject):
    progress = pyqtSignal(str, str)  
    finished = pyqtSignal(dict)       
    failed = pyqtSignal(str)

    def __init__(self, src_path: Path, description: str, user_id: str,
                 usb_path: Optional[str], storage_password: Optional[str], 
                 keys_storage: str, file_storage: str):
        super().__init__()
        self.src_path = src_path
        self.description = description or ""
        self.usb_path = usb_path or None
        self.storage_password = storage_password or None
        self.user_id = user_id
        self.keys_storage = keys_storage
        self.file_storage = file_storage

    def run(self):
        try:
            filename = secure_filename(self.src_path.name)
            dst = UPLOAD_DIR / filename
            if dst.resolve() != self.src_path.resolve():
                shutil.copy2(self.src_path, dst)

            ext = dst.suffix
            filepath = str(dst)

            self.progress.emit(f"ℹ️ [Enrollment] Starting enrollment at {time.strftime('%H:%M:%S')}…", "info")
            self.progress.emit("   • Generating ephemeral key and hashing", "info")
            self.progress.emit("   • Encrypting file content", "info")
            self.progress.emit("   • Encrypting description and serializing keys", "info")

            start = time.time()
            success, file_info, msg = enrollment_protocol(
                filepath, filename, self.description, ext, self.user_id,
                external_path=self.usb_path, external_pw=self.storage_password,
                keys_storage=self.keys_storage, file_storage=self.file_storage
            )
            duration = time.time() - start

            if not success:
                self.progress.emit(f"❌ Enrollment failed: {msg}", "error")
                self.finished.emit({"success": False, "message": msg, "duration": duration})
                return

            info_dict: Dict[str, Any] = getattr(file_info, "__dict__", None) or dict(file_info)
            self.progress.emit(f"✅ Enrollment completed in {duration:.2f}s!", "success")
            self.progress.emit(f"   • Keys stored to: {self.keys_storage.upper()}", "info")
            self.progress.emit(f"   • Encrypted file stored to: {self.file_storage.upper()}", "info")
            
            if 'info_file_path' in info_dict:
                self.progress.emit(f"   • File info saved to: {info_dict['info_file_path']}", "info")

            self.finished.emit({
                "success": True,
                "file_info": info_dict,
                "user_id": self.user_id,
                "usb_path": self.usb_path,
                "storage_password": self.storage_password,
                "keys_storage": self.keys_storage,
                "file_storage": self.file_storage,
                "duration": duration,
            })

        except Exception as e:
            err = f"Enrollment exception: {e}\n{traceback.format_exc()}"
            self.progress.emit(f"❌ {err}", "error")
            self.failed.emit(err)
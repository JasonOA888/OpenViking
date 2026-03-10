# Copyright (c) 2026 Beijing Volcano Engine Technology Co., Ltd.
# SPDX-License-Identifier: Apache-2.0
"""
Instance lock for VikingFS (Issue #473).

Prevents multiple stdio MCP sessions from conflicting for the same data directory.
"""

import os
import fcntl
from datetime import datetime
from typing import Optional

from openviking.storage.errors import StorageException
from openviking_cli.utils.logger import get_logger

logger = get_logger(__name__)


class VikingFSInstanceLock:
    """File-based lock to prevent multiple VikingFS instances.
    
    Uses flock (advisory lock) for cross-process synchronization.
    The lock is held for the lifetime of the process.
    """
    
    _instance: Optional["VikingFSInstanceLock"] = None
    _lock_fd: Optional[int] = None
    
    def __init__(self, data_dir: str):
        self.data_dir = data_dir
        self.lock_file = os.path.join(data_dir, ".vikingfs.lock")
        self._acquired = False
        
    @classmethod
    def acquire(cls, data_dir: str) -> "VikingFSInstanceLock":
        """Acquire exclusive lock for data directory.
        
        Args:
            data_dir: Path to OpenViking data directory
            
        Returns:
            VikingFSInstanceLock instance if successful
            
        Raises:
            StorageException: If another instance already holds the lock
        """
        if cls._instance is not None:
            # Already acquired in this process
            return cls._instance
            
        lock = cls(data_dir)
        
        try:
            # Create lock directory if needed
            os.makedirs(data_dir, exist_ok=True)
            
            # Open lock file (create if needed)
            cls._lock_fd = os.open(
                lock.lock_file,
                os.O_CREAT | os.O_RDWR,
                0o644
            )
            
            # Try to acquire exclusive lock (non-blocking)
            try:
                fcntl.flock(cls._lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except (IOError, OSError) as e:
                # Lock held by another process
                os.close(cls._lock_fd)
                cls._lock_fd = None
                
                raise StorageException(
                    f"OpenViking data directory is already in use by another instance. "
                    f"Only one OpenViking instance can access a data directory at a time. "
                    f"\n\n"
                    f"If running multiple MCP sessions, use a single shared HTTP MCP server "
                    f"instead of stdio (per-session). "
                    f"\n\n"
                    f"See: https://github.com/volcengine/OpenViking/issues/473"
                )
            
            # Write PID and timestamp for debugging
            pid_info = f"{os.getpid()}\n{datetime.now().isoformat()}\n"
            os.write(cls._lock_fd, pid_info.encode())
            
            lock._acquired = True
            cls._instance = lock
            
            logger.info(
                f"Acquired VikingFS instance lock: PID={os.getpid()}, data_dir={data_dir}"
            )
            
            return lock
            
        except Exception as e:
            logger.error(f"Failed to acquire instance lock: {e}")
            raise
    
    @classmethod
    def release(cls):
        """Release the lock on process exit."""
        if cls._lock_fd is not None:
            try:
                fcntl.flock(cls._lock_fd, fcntl.LOCK_UN)
                os.close(cls._lock_fd)
                # Don't delete lock file - it will be reused
                logger.info(f"Released VikingFS instance lock: PID={os.getpid()}")
            except Exception as e:
                logger.warning(f"Failed to release instance lock: {e}")
            finally:
                cls._lock_fd = None
                cls._instance = None

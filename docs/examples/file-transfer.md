# File Transfer Example

This example demonstrates how to implement efficient file transfer functionality using the Pyvider RPC Plugin framework with streaming RPC calls.

## Overview

The File Transfer service provides:

- **File upload** - Client to server streaming
- **File download** - Server to client streaming  
- **File listing** - Directory browsing
- **File metadata** - Size, modification time, permissions
- **Chunked transfer** - Efficient handling of large files
- **Resume capability** - Interrupted transfer recovery
- **Progress tracking** - Transfer progress callbacks

## Service Definition

**file_transfer.proto**
```protobuf
syntax = "proto3";

package filetransfer;

service FileTransferService {
  // Upload file from client to server
  rpc UploadFile(stream FileChunk) returns (FileUploadResponse);
  
  // Download file from server to client
  rpc DownloadFile(FileDownloadRequest) returns (stream FileChunk);
  
  // List files in directory
  rpc ListFiles(ListFilesRequest) returns (ListFilesResponse);
  
  // Get file metadata
  rpc GetFileInfo(FileInfoRequest) returns (FileInfoResponse);
  
  // Delete file
  rpc DeleteFile(DeleteFileRequest) returns (DeleteFileResponse);
}

message FileChunk {
  string filename = 1;
  int64 offset = 2;
  bytes data = 3;
  int64 total_size = 4;
  string checksum = 5;  // MD5 hash of chunk
}

message FileUploadResponse {
  bool success = 1;
  string message = 2;
  string filename = 3;
  int64 bytes_uploaded = 4;
  string checksum = 5;  // Final file checksum
}

message FileDownloadRequest {
  string filename = 1;
  int64 start_offset = 2;  // For resume capability
  int64 max_chunk_size = 3;
}

message ListFilesRequest {
  string directory = 1;
  bool recursive = 2;
  string pattern = 3;  // File pattern filter
}

message ListFilesResponse {
  repeated FileInfo files = 1;
}

message FileInfo {
  string name = 1;
  string path = 2;
  int64 size = 3;
  int64 modified_time = 4;
  bool is_directory = 5;
  string permissions = 6;
  string checksum = 7;
}

message FileInfoRequest {
  string filename = 1;
}

message FileInfoResponse {
  FileInfo file_info = 1;
  bool exists = 2;
}

message DeleteFileRequest {
  string filename = 1;
}

message DeleteFileResponse {
  bool success = 1;
  string message = 2;
}
```

Generate Python code:
```bash
python -m grpc_tools.protoc --python_out=. --grpc_python_out=. file_transfer.proto
```

## Server Implementation

**file_transfer_service.py**
```python
import asyncio
import hashlib
import os
import time
import logging
from pathlib import Path
from typing import AsyncIterator
import grpc
from grpc.aio import ServicerContext

from file_transfer_pb2 import (
    FileChunk, FileUploadResponse, FileDownloadRequest, 
    ListFilesRequest, ListFilesResponse, FileInfo,
    FileInfoRequest, FileInfoResponse,
    DeleteFileRequest, DeleteFileResponse
)
from file_transfer_pb2_grpc import (
    FileTransferServiceServicer, 
    add_FileTransferServiceServicer_to_server
)
from pyvider.server import RPCPluginServer
from pyvider.config import ServerConfig, TransportConfig

logger = logging.getLogger(__name__)

class FileTransferServicer(FileTransferServiceServicer):
    """File transfer service implementation."""
    
    def __init__(self, storage_directory: str = "./storage"):
        self.storage_dir = Path(storage_directory)
        self.storage_dir.mkdir(exist_ok=True)
        self.max_chunk_size = 1024 * 1024  # 1MB chunks
        logger.info(f"File transfer service initialized, storage: {self.storage_dir}")
    
    async def UploadFile(
        self, 
        request_iterator: AsyncIterator[FileChunk], 
        context: ServicerContext
    ) -> FileUploadResponse:
        """Handle file upload from client."""
        filename = None
        total_bytes = 0
        expected_size = 0
        file_hash = hashlib.md5()
        temp_file_path = None
        
        try:
            async for chunk in request_iterator:
                if filename is None:
                    # First chunk contains metadata
                    filename = chunk.filename
                    expected_size = chunk.total_size
                    
                    # Validate filename (security check)
                    if not self._is_safe_filename(filename):
                        await context.abort(
                            grpc.StatusCode.INVALID_ARGUMENT,
                            f"Invalid filename: {filename}"
                        )
                        return
                    
                    temp_file_path = self.storage_dir / f"{filename}.tmp"
                    logger.info(f"Starting upload: {filename} ({expected_size} bytes)")
                
                # Verify chunk offset
                if chunk.offset != total_bytes:
                    await context.abort(
                        grpc.StatusCode.INVALID_ARGUMENT,
                        f"Invalid chunk offset: expected {total_bytes}, got {chunk.offset}"
                    )
                    return
                
                # Write chunk to temporary file
                with open(temp_file_path, "ab") as f:
                    f.write(chunk.data)
                
                total_bytes += len(chunk.data)
                file_hash.update(chunk.data)
                
                # Verify chunk checksum if provided
                if chunk.checksum:
                    chunk_hash = hashlib.md5(chunk.data).hexdigest()
                    if chunk_hash != chunk.checksum:
                        await context.abort(
                            grpc.StatusCode.DATA_LOSS,
                            "Chunk checksum verification failed"
                        )
                        return
                
                logger.debug(f"Received chunk: {len(chunk.data)} bytes, total: {total_bytes}")
            
            # Verify total size
            if total_bytes != expected_size:
                await context.abort(
                    grpc.StatusCode.INVALID_ARGUMENT,
                    f"File size mismatch: expected {expected_size}, got {total_bytes}"
                )
                return
            
            # Move temp file to final location
            final_path = self.storage_dir / filename
            temp_file_path.rename(final_path)
            
            final_checksum = file_hash.hexdigest()
            logger.info(f"Upload completed: {filename} ({total_bytes} bytes, {final_checksum})")
            
            return FileUploadResponse(
                success=True,
                message="File uploaded successfully",
                filename=filename,
                bytes_uploaded=total_bytes,
                checksum=final_checksum
            )
        
        except Exception as e:
            logger.error(f"Upload failed: {e}")
            
            # Cleanup temp file on error
            if temp_file_path and temp_file_path.exists():
                temp_file_path.unlink()
            
            return FileUploadResponse(
                success=False,
                message=f"Upload failed: {e}",
                filename=filename or "",
                bytes_uploaded=total_bytes
            )
    
    async def DownloadFile(
        self, 
        request: FileDownloadRequest, 
        context: ServicerContext
    ) -> AsyncIterator[FileChunk]:
        """Handle file download to client."""
        filename = request.filename
        
        # Validate filename
        if not self._is_safe_filename(filename):
            await context.abort(
                grpc.StatusCode.INVALID_ARGUMENT,
                f"Invalid filename: {filename}"
            )
            return
        
        file_path = self.storage_dir / filename
        
        if not file_path.exists():
            await context.abort(
                grpc.StatusCode.NOT_FOUND,
                f"File not found: {filename}"
            )
            return
        
        if not file_path.is_file():
            await context.abort(
                grpc.StatusCode.INVALID_ARGUMENT,
                f"Not a file: {filename}"
            )
            return
        
        file_size = file_path.stat().st_size
        start_offset = request.start_offset
        chunk_size = min(request.max_chunk_size or self.max_chunk_size, self.max_chunk_size)
        
        logger.info(f"Starting download: {filename} ({file_size} bytes, offset: {start_offset})")
        
        try:
            with open(file_path, "rb") as f:
                f.seek(start_offset)
                offset = start_offset
                
                while True:
                    if context.cancelled():
                        logger.info(f"Download cancelled: {filename}")
                        break
                    
                    data = f.read(chunk_size)
                    if not data:
                        break
                    
                    # Calculate chunk checksum
                    chunk_checksum = hashlib.md5(data).hexdigest()
                    
                    chunk = FileChunk(
                        filename=filename,
                        offset=offset,
                        data=data,
                        total_size=file_size,
                        checksum=chunk_checksum
                    )
                    
                    yield chunk
                    
                    offset += len(data)
                    logger.debug(f"Sent chunk: {len(data)} bytes, offset: {offset}")
                    
                    # Small delay to prevent overwhelming the client
                    await asyncio.sleep(0.001)
            
            logger.info(f"Download completed: {filename} ({offset - start_offset} bytes)")
        
        except Exception as e:
            logger.error(f"Download failed: {e}")
            await context.abort(
                grpc.StatusCode.INTERNAL,
                f"Download failed: {e}"
            )
    
    async def ListFiles(
        self, 
        request: ListFilesRequest, 
        context: ServicerContext
    ) -> ListFilesResponse:
        """List files in directory."""
        directory = request.directory or "."
        
        # Security check - prevent directory traversal
        if ".." in directory or directory.startswith("/"):
            await context.abort(
                grpc.StatusCode.PERMISSION_DENIED,
                "Directory traversal not allowed"
            )
            return
        
        base_path = self.storage_dir / directory
        
        if not base_path.exists():
            await context.abort(
                grpc.StatusCode.NOT_FOUND,
                f"Directory not found: {directory}"
            )
            return
        
        files = []
        
        try:
            if request.recursive:
                # Recursive listing
                for file_path in base_path.rglob("*"):
                    if self._matches_pattern(file_path.name, request.pattern):
                        file_info = await self._get_file_info(file_path)
                        files.append(file_info)
            else:
                # Non-recursive listing
                for file_path in base_path.iterdir():
                    if self._matches_pattern(file_path.name, request.pattern):
                        file_info = await self._get_file_info(file_path)
                        files.append(file_info)
            
            logger.info(f"Listed {len(files)} files in {directory}")
            
            return ListFilesResponse(files=files)
        
        except Exception as e:
            logger.error(f"List files failed: {e}")
            await context.abort(
                grpc.StatusCode.INTERNAL,
                f"List files failed: {e}"
            )
    
    async def GetFileInfo(
        self, 
        request: FileInfoRequest, 
        context: ServicerContext
    ) -> FileInfoResponse:
        """Get file metadata."""
        filename = request.filename
        
        if not self._is_safe_filename(filename):
            await context.abort(
                grpc.StatusCode.INVALID_ARGUMENT,
                f"Invalid filename: {filename}"
            )
            return
        
        file_path = self.storage_dir / filename
        
        if not file_path.exists():
            return FileInfoResponse(
                file_info=FileInfo(),
                exists=False
            )
        
        try:
            file_info = await self._get_file_info(file_path)
            
            return FileInfoResponse(
                file_info=file_info,
                exists=True
            )
        
        except Exception as e:
            logger.error(f"Get file info failed: {e}")
            await context.abort(
                grpc.StatusCode.INTERNAL,
                f"Get file info failed: {e}"
            )
    
    async def DeleteFile(
        self, 
        request: DeleteFileRequest, 
        context: ServicerContext
    ) -> DeleteFileResponse:
        """Delete file."""
        filename = request.filename
        
        if not self._is_safe_filename(filename):
            await context.abort(
                grpc.StatusCode.INVALID_ARGUMENT,
                f"Invalid filename: {filename}"
            )
            return
        
        file_path = self.storage_dir / filename
        
        if not file_path.exists():
            return DeleteFileResponse(
                success=False,
                message=f"File not found: {filename}"
            )
        
        if not file_path.is_file():
            return DeleteFileResponse(
                success=False,
                message=f"Not a file: {filename}"
            )
        
        try:
            file_path.unlink()
            logger.info(f"File deleted: {filename}")
            
            return DeleteFileResponse(
                success=True,
                message=f"File deleted successfully: {filename}"
            )
        
        except Exception as e:
            logger.error(f"Delete file failed: {e}")
            return DeleteFileResponse(
                success=False,
                message=f"Delete failed: {e}"
            )
    
    def _is_safe_filename(self, filename: str) -> bool:
        """Check if filename is safe (no directory traversal)."""
        if not filename or filename.startswith("."):
            return False
        
        # Check for directory traversal
        if ".." in filename or "/" in filename or "\\" in filename:
            return False
        
        # Check for system files
        system_files = {"CON", "PRN", "AUX", "NUL"} 
        if filename.upper() in system_files:
            return False
        
        return True
    
    def _matches_pattern(self, filename: str, pattern: str | None) -> bool:
        """Check if filename matches pattern."""
        if not pattern:
            return True
        
        import fnmatch
        return fnmatch.fnmatch(filename.lower(), pattern.lower())
    
    async def _get_file_info(self, file_path: Path) -> FileInfo:
        """Get file information."""
        stat_info = file_path.stat()
        
        # Calculate file checksum if it's a regular file and not too large
        checksum = ""
        if file_path.is_file() and stat_info.st_size < 10 * 1024 * 1024:  # 10MB limit
            try:
                hash_md5 = hashlib.md5()
                with open(file_path, "rb") as f:
                    for chunk in iter(lambda: f.read(4096), b""):
                        hash_md5.update(chunk)
                checksum = hash_md5.hexdigest()
            except Exception:
                pass  # Ignore checksum calculation errors
        
        return FileInfo(
            name=file_path.name,
            path=str(file_path.relative_to(self.storage_dir)),
            size=stat_info.st_size,
            modified_time=int(stat_info.st_mtime),
            is_directory=file_path.is_dir(),
            permissions=oct(stat_info.st_mode)[-3:],
            checksum=checksum
        )


async def create_file_transfer_server(storage_dir: str = "./storage"):
    """Create file transfer server."""
    config = ServerConfig(
        transport=TransportConfig(
            host="localhost",
            port=50051,
            tls_enabled=False
        ),
        max_workers=10,
        log_level="INFO"
    )
    
    server = RPCPluginServer(config)
    
    # Add file transfer service
    file_service = FileTransferServicer(storage_dir)
    server.add_service(file_service)
    
    return server


async def main():
    """Run file transfer server."""
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    server = await create_file_transfer_server()
    
    try:
        await server.start()
        logger.info("File transfer server started. Press Ctrl+C to stop.")
        
        while True:
            await asyncio.sleep(1)
    
    except KeyboardInterrupt:
        logger.info("Shutting down server...")
    
    finally:
        await server.stop()


if __name__ == "__main__":
    asyncio.run(main())
```

## Client Implementation

**file_transfer_client.py**
```python
import asyncio
import hashlib
import logging
import os
import time
from pathlib import Path
from typing import Callable, AsyncIterator
import grpc

from file_transfer_pb2 import (
    FileChunk, FileDownloadRequest, ListFilesRequest,
    FileInfoRequest, DeleteFileRequest
)
from file_transfer_pb2_grpc import FileTransferServiceStub

logger = logging.getLogger(__name__)

class FileTransferClient:
    """File transfer client implementation."""
    
    def __init__(self, host: str = "localhost", port: int = 50051):
        self.channel = grpc.aio.insecure_channel(f"{host}:{port}")
        self.stub = FileTransferServiceStub(self.channel)
        self.chunk_size = 1024 * 1024  # 1MB chunks
        logger.info(f"File transfer client connected to {host}:{port}")
    
    async def upload_file(
        self, 
        local_path: str, 
        remote_filename: str | None = None,
        progress_callback: Callable[[int, int], None] | None = None
    ) -> bool:
        """Upload file to server."""
        local_file = Path(local_path)
        
        if not local_file.exists():
            logger.error(f"Local file not found: {local_path}")
            return False
        
        if not local_file.is_file():
            logger.error(f"Not a file: {local_path}")
            return False
        
        remote_filename = remote_filename or local_file.name
        file_size = local_file.stat().st_size
        
        logger.info(f"Uploading {local_path} -> {remote_filename} ({file_size} bytes)")
        
        async def chunk_generator() -> AsyncIterator[FileChunk]:
            with open(local_file, "rb") as f:
                offset = 0
                
                while True:
                    data = f.read(self.chunk_size)
                    if not data:
                        break
                    
                    # Calculate chunk checksum
                    chunk_checksum = hashlib.md5(data).hexdigest()
                    
                    chunk = FileChunk(
                        filename=remote_filename,
                        offset=offset,
                        data=data,
                        total_size=file_size,
                        checksum=chunk_checksum
                    )
                    
                    yield chunk
                    
                    offset += len(data)
                    
                    # Call progress callback
                    if progress_callback:
                        progress_callback(offset, file_size)
                    
                    logger.debug(f"Sending chunk: {len(data)} bytes, offset: {offset}")
        
        try:
            response = await self.stub.UploadFile(chunk_generator())
            
            if response.success:
                logger.info(f"Upload successful: {response.message}")
                logger.info(f"Server checksum: {response.checksum}")
                return True
            else:
                logger.error(f"Upload failed: {response.message}")
                return False
        
        except grpc.RpcError as e:
            logger.error(f"Upload RPC failed: {e.code()}: {e.details()}")
            return False
    
    async def download_file(
        self, 
        remote_filename: str, 
        local_path: str,
        resume: bool = False,
        progress_callback: Callable[[int, int], None] | None = None
    ) -> bool:
        """Download file from server."""
        local_file = Path(local_path)
        
        # Determine start offset for resume
        start_offset = 0
        if resume and local_file.exists():
            start_offset = local_file.stat().st_size
            logger.info(f"Resuming download from offset: {start_offset}")
        
        request = FileDownloadRequest(
            filename=remote_filename,
            start_offset=start_offset,
            max_chunk_size=self.chunk_size
        )
        
        logger.info(f"Downloading {remote_filename} -> {local_path}")
        
        try:
            # Create parent directory if needed
            local_file.parent.mkdir(parents=True, exist_ok=True)
            
            # Open file in append mode if resuming, otherwise write mode
            mode = "ab" if resume and start_offset > 0 else "wb"
            file_hash = hashlib.md5()
            total_downloaded = start_offset
            total_size = 0
            
            with open(local_file, mode) as f:
                async for chunk in self.stub.DownloadFile(request):
                    if total_size == 0:
                        total_size = chunk.total_size
                        logger.info(f"Download size: {total_size} bytes")
                    
                    # Verify chunk checksum
                    chunk_checksum = hashlib.md5(chunk.data).hexdigest()
                    if chunk_checksum != chunk.checksum:
                        logger.error("Chunk checksum verification failed")
                        return False
                    
                    # Verify chunk offset
                    if chunk.offset != total_downloaded:
                        logger.error(f"Chunk offset mismatch: expected {total_downloaded}, got {chunk.offset}")
                        return False
                    
                    f.write(chunk.data)
                    file_hash.update(chunk.data)
                    total_downloaded += len(chunk.data)
                    
                    # Call progress callback
                    if progress_callback:
                        progress_callback(total_downloaded, total_size)
                    
                    logger.debug(f"Received chunk: {len(chunk.data)} bytes, total: {total_downloaded}")
            
            logger.info(f"Download completed: {total_downloaded} bytes")
            logger.info(f"File checksum: {file_hash.hexdigest()}")
            return True
        
        except grpc.RpcError as e:
            logger.error(f"Download RPC failed: {e.code()}: {e.details()}")
            return False
        except Exception as e:
            logger.error(f"Download failed: {e}")
            return False
    
    async def list_files(self, directory: str = ".", recursive: bool = False, pattern: str = "*") -> list:
        """List files on server."""
        request = ListFilesRequest(
            directory=directory,
            recursive=recursive,
            pattern=pattern
        )
        
        try:
            response = await self.stub.ListFiles(request)
            
            files = []
            for file_info in response.files:
                files.append({
                    'name': file_info.name,
                    'path': file_info.path,
                    'size': file_info.size,
                    'modified': time.ctime(file_info.modified_time),
                    'is_directory': file_info.is_directory,
                    'permissions': file_info.permissions,
                    'checksum': file_info.checksum
                })
            
            logger.info(f"Listed {len(files)} files in {directory}")
            return files
        
        except grpc.RpcError as e:
            logger.error(f"List files RPC failed: {e.code()}: {e.details()}")
            return []
    
    async def get_file_info(self, filename: str) -> dict | None:
        """Get file information."""
        request = FileInfoRequest(filename=filename)
        
        try:
            response = await self.stub.GetFileInfo(request)
            
            if not response.exists:
                return None
            
            file_info = response.file_info
            return {
                'name': file_info.name,
                'path': file_info.path,
                'size': file_info.size,
                'modified': time.ctime(file_info.modified_time),
                'is_directory': file_info.is_directory,
                'permissions': file_info.permissions,
                'checksum': file_info.checksum
            }
        
        except grpc.RpcError as e:
            logger.error(f"Get file info RPC failed: {e.code()}: {e.details()}")
            return None
    
    async def delete_file(self, filename: str) -> bool:
        """Delete file on server."""
        request = DeleteFileRequest(filename=filename)
        
        try:
            response = await self.stub.DeleteFile(request)
            
            if response.success:
                logger.info(f"File deleted: {filename}")
                return True
            else:
                logger.error(f"Delete failed: {response.message}")
                return False
        
        except grpc.RpcError as e:
            logger.error(f"Delete file RPC failed: {e.code()}: {e.details()}")
            return False
    
    async def close(self):
        """Close client connection."""
        await self.channel.close()
        logger.info("File transfer client closed")


def progress_bar(current: int, total: int, width: int = 50):
    """Display progress bar."""
    percent = (current / total) * 100
    filled = int(width * current // total)
    bar = '█' * filled + '-' * (width - filled)
    print(f'\r|{bar}| {percent:.1f}% ({current}/{total} bytes)', end='', flush=True)


async def demo_file_transfer():
    """Demonstrate file transfer functionality."""
    client = FileTransferClient()
    
    try:
        # Create a test file
        test_file = Path("test_upload.txt")
        with open(test_file, "w") as f:
            f.write("Hello, World! This is a test file for upload.\n" * 1000)
        
        print(f"Created test file: {test_file} ({test_file.stat().st_size} bytes)")
        
        # Upload file
        print("\n1. Uploading file...")
        success = await client.upload_file(
            str(test_file), 
            "uploaded_test.txt",
            progress_callback=progress_bar
        )
        print(f"\nUpload {'successful' if success else 'failed'}")
        
        # List files
        print("\n2. Listing files...")
        files = await client.list_files()
        for file_info in files:
            print(f"  {file_info['name']} ({file_info['size']} bytes)")
        
        # Get file info
        print("\n3. Getting file info...")
        info = await client.get_file_info("uploaded_test.txt")
        if info:
            print(f"  File: {info['name']}")
            print(f"  Size: {info['size']} bytes")
            print(f"  Modified: {info['modified']}")
            print(f"  Checksum: {info['checksum']}")
        
        # Download file
        print("\n4. Downloading file...")
        download_path = "downloaded_test.txt"
        success = await client.download_file(
            "uploaded_test.txt",
            download_path,
            progress_callback=progress_bar
        )
        print(f"\nDownload {'successful' if success else 'failed'}")
        
        # Verify download
        if Path(download_path).exists():
            original_size = test_file.stat().st_size
            downloaded_size = Path(download_path).stat().st_size
            print(f"Original: {original_size} bytes, Downloaded: {downloaded_size} bytes")
            print(f"Verification: {'PASS' if original_size == downloaded_size else 'FAIL'}")
        
        # Clean up test files
        test_file.unlink()
        if Path(download_path).exists():
            Path(download_path).unlink()
    
    finally:
        await client.close()


async def main():
    """Run file transfer client demo."""
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    try:
        await demo_file_transfer()
    except Exception as e:
        logger.error(f"Demo failed: {e}")
        raise


if __name__ == "__main__":
    asyncio.run(main())
```

## Command Line Interface

**file_cli.py**
```python
import asyncio
import argparse
import logging
import sys
from pathlib import Path
from file_transfer_client import FileTransferClient, progress_bar

async def main():
    """Command line interface for file transfer."""
    parser = argparse.ArgumentParser(description="File Transfer Client")
    parser.add_argument("--host", default="localhost", help="Server host")
    parser.add_argument("--port", type=int, default=50051, help="Server port")
    
    subparsers = parser.add_subparsers(dest="command", help="Commands")
    
    # Upload command
    upload_parser = subparsers.add_parser("upload", help="Upload file")
    upload_parser.add_argument("local_file", help="Local file to upload")
    upload_parser.add_argument("--remote-name", help="Remote filename")
    
    # Download command
    download_parser = subparsers.add_parser("download", help="Download file")
    download_parser.add_argument("remote_file", help="Remote file to download")
    download_parser.add_argument("local_file", help="Local file path")
    download_parser.add_argument("--resume", action="store_true", help="Resume download")
    
    # List command
    list_parser = subparsers.add_parser("list", help="List files")
    list_parser.add_argument("--directory", default=".", help="Directory to list")
    list_parser.add_argument("--recursive", action="store_true", help="Recursive listing")
    list_parser.add_argument("--pattern", help="File pattern")
    
    # Info command
    info_parser = subparsers.add_parser("info", help="Get file info")
    info_parser.add_argument("filename", help="Filename")
    
    # Delete command
    delete_parser = subparsers.add_parser("delete", help="Delete file")
    delete_parser.add_argument("filename", help="Filename to delete")
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return
    
    # Setup logging
    logging.basicConfig(level=logging.WARNING)
    
    client = FileTransferClient(args.host, args.port)
    
    try:
        if args.command == "upload":
            success = await client.upload_file(
                args.local_file,
                args.remote_name,
                progress_callback=progress_bar
            )
            print(f"\nUpload {'successful' if success else 'failed'}")
            sys.exit(0 if success else 1)
        
        elif args.command == "download":
            success = await client.download_file(
                args.remote_file,
                args.local_file,
                resume=args.resume,
                progress_callback=progress_bar
            )
            print(f"\nDownload {'successful' if success else 'failed'}")
            sys.exit(0 if success else 1)
        
        elif args.command == "list":
            files = await client.list_files(
                args.directory,
                args.recursive,
                args.pattern
            )
            
            for file_info in files:
                size_str = f"{file_info['size']:>10}"
                type_str = "DIR" if file_info['is_directory'] else "FILE"
                print(f"{type_str:>4} {size_str} {file_info['name']}")
        
        elif args.command == "info":
            info = await client.get_file_info(args.filename)
            if info:
                print(f"Name: {info['name']}")
                print(f"Size: {info['size']} bytes")
                print(f"Modified: {info['modified']}")
                print(f"Type: {'Directory' if info['is_directory'] else 'File'}")
                print(f"Permissions: {info['permissions']}")
                if info['checksum']:
                    print(f"Checksum: {info['checksum']}")
            else:
                print("File not found")
                sys.exit(1)
        
        elif args.command == "delete":
            success = await client.delete_file(args.filename)
            sys.exit(0 if success else 1)
    
    finally:
        await client.close()


if __name__ == "__main__":
    asyncio.run(main())
```

## Usage Examples

### Start the Server
```bash
python file_transfer_service.py
```

### Command Line Usage
```bash
# Upload file
python file_cli.py upload document.pdf --remote-name shared_doc.pdf

# Download file
python file_cli.py download shared_doc.pdf ./downloads/document.pdf

# Resume interrupted download
python file_cli.py download large_file.zip ./downloads/large_file.zip --resume

# List files
python file_cli.py list
python file_cli.py list --directory uploads --recursive

# Get file information
python file_cli.py info shared_doc.pdf

# Delete file
python file_cli.py delete old_file.txt
```

### Programmatic Usage
```python
async def example_usage():
    client = FileTransferClient()
    
    # Upload with progress tracking
    await client.upload_file(
        "large_video.mp4",
        progress_callback=lambda current, total: 
            print(f"Upload: {current/total*100:.1f}%")
    )
    
    # Download with resume capability
    await client.download_file(
        "backup.zip",
        "./downloads/backup.zip", 
        resume=True
    )
    
    await client.close()
```

## Key Features Demonstrated

1. **Streaming Transfers** - Efficient handling of large files
2. **Checksums** - Data integrity verification
3. **Resume Capability** - Recover from interrupted transfers
4. **Progress Tracking** - Real-time transfer progress
5. **Security** - Filename validation and sandboxing
6. **Error Handling** - Comprehensive error management
7. **CLI Interface** - Command-line tool for easy usage
8. **Metadata Support** - File information and directory listing

This file transfer implementation provides a production-ready foundation for file sharing services and can be extended with features like authentication, encryption, and compression.
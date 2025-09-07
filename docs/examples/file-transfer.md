# File Transfer Example

Implement efficient file transfer functionality using Pyvider RPC Plugin with streaming RPC calls.

## Features

- **File upload/download** - Streaming transfers with chunked data
- **File management** - Directory listing, metadata, deletion
- **Resume capability** - Interrupted transfer recovery
- **Progress tracking** - Real-time transfer monitoring
- **Security** - Filename validation and path traversal protection

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
import logging
from pathlib import Path
from typing import AsyncIterator
import grpc
from grpc.aio import ServicerContext

from file_transfer_pb2 import *
from file_transfer_pb2_grpc import *
from pyvider.server import RPCPluginServer
from pyvider.config import ServerConfig, TransportConfig

logger = logging.getLogger(__name__)

class FileTransferServicer(FileTransferServiceServicer):
    """File transfer service implementation."""
    
    def __init__(self, storage_directory: str = "./storage"):
        self.storage_dir = Path(storage_directory)
        self.storage_dir.mkdir(exist_ok=True)
        self.max_chunk_size = 1024 * 1024  # 1MB chunks
    
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
                    filename = chunk.filename
                    expected_size = chunk.total_size
                    
                    if not self._is_safe_filename(filename):
                        await context.abort(
                            grpc.StatusCode.INVALID_ARGUMENT,
                            f"Invalid filename: {filename}"
                        )
                    
                    temp_file_path = self.storage_dir / f"{filename}.tmp"
                
                # Verify chunk integrity
                if chunk.offset != total_bytes:
                    await context.abort(
                        grpc.StatusCode.INVALID_ARGUMENT,
                        f"Invalid chunk offset: expected {total_bytes}, got {chunk.offset}"
                    )
                
                if chunk.checksum:
                    chunk_hash = hashlib.md5(chunk.data).hexdigest()
                    if chunk_hash != chunk.checksum:
                        await context.abort(grpc.StatusCode.DATA_LOSS, "Chunk checksum failed")
                
                # Write chunk data
                with open(temp_file_path, "ab") as f:
                    f.write(chunk.data)
                
                total_bytes += len(chunk.data)
                file_hash.update(chunk.data)
            
            # Verify and finalize
            if total_bytes != expected_size:
                await context.abort(
                    grpc.StatusCode.INVALID_ARGUMENT,
                    f"Size mismatch: expected {expected_size}, got {total_bytes}"
                )
            
            final_path = self.storage_dir / filename
            temp_file_path.rename(final_path)
            
            return FileUploadResponse(
                success=True,
                message="File uploaded successfully",
                filename=filename,
                bytes_uploaded=total_bytes,
                checksum=file_hash.hexdigest()
            )
        
        except Exception as e:
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
        
        if not self._is_safe_filename(filename):
            await context.abort(grpc.StatusCode.INVALID_ARGUMENT, f"Invalid filename: {filename}")
        
        file_path = self.storage_dir / filename
        if not file_path.exists() or not file_path.is_file():
            await context.abort(grpc.StatusCode.NOT_FOUND, f"File not found: {filename}")
        
        file_size = file_path.stat().st_size
        start_offset = request.start_offset
        chunk_size = min(request.max_chunk_size or self.max_chunk_size, self.max_chunk_size)
        
        try:
            with open(file_path, "rb") as f:
                f.seek(start_offset)
                offset = start_offset
                
                while True:
                    if context.cancelled():
                        break
                    
                    data = f.read(chunk_size)
                    if not data:
                        break
                    
                    yield FileChunk(
                        filename=filename,
                        offset=offset,
                        data=data,
                        total_size=file_size,
                        checksum=hashlib.md5(data).hexdigest()
                    )
                    
                    offset += len(data)
                    await asyncio.sleep(0.001)  # Prevent overwhelming client
        
        except Exception as e:
            await context.abort(grpc.StatusCode.INTERNAL, f"Download failed: {e}")
    
    async def ListFiles(
        self, 
        request: ListFilesRequest, 
        context: ServicerContext
    ) -> ListFilesResponse:
        """List files in directory."""
        directory = request.directory or "."
        
        if ".." in directory or directory.startswith("/"):
            await context.abort(grpc.StatusCode.PERMISSION_DENIED, "Directory traversal not allowed")
        
        base_path = self.storage_dir / directory
        if not base_path.exists():
            await context.abort(grpc.StatusCode.NOT_FOUND, f"Directory not found: {directory}")
        
        try:
            files = []
            paths = base_path.rglob("*") if request.recursive else base_path.iterdir()
            
            for file_path in paths:
                if self._matches_pattern(file_path.name, request.pattern):
                    files.append(await self._get_file_info(file_path))
            
            return ListFilesResponse(files=files)
        
        except Exception as e:
            await context.abort(grpc.StatusCode.INTERNAL, f"List files failed: {e}")
    
    async def GetFileInfo(
        self, 
        request: FileInfoRequest, 
        context: ServicerContext
    ) -> FileInfoResponse:
        """Get file metadata."""
        filename = request.filename
        
        if not self._is_safe_filename(filename):
            await context.abort(grpc.StatusCode.INVALID_ARGUMENT, f"Invalid filename: {filename}")
        
        file_path = self.storage_dir / filename
        if not file_path.exists():
            return FileInfoResponse(file_info=FileInfo(), exists=False)
        
        try:
            return FileInfoResponse(file_info=await self._get_file_info(file_path), exists=True)
        except Exception as e:
            await context.abort(grpc.StatusCode.INTERNAL, f"Get file info failed: {e}")
    
    async def DeleteFile(
        self, 
        request: DeleteFileRequest, 
        context: ServicerContext
    ) -> DeleteFileResponse:
        """Delete file."""
        filename = request.filename
        
        if not self._is_safe_filename(filename):
            await context.abort(grpc.StatusCode.INVALID_ARGUMENT, f"Invalid filename: {filename}")
        
        file_path = self.storage_dir / filename
        if not file_path.exists() or not file_path.is_file():
            return DeleteFileResponse(success=False, message=f"File not found: {filename}")
        
        try:
            file_path.unlink()
            return DeleteFileResponse(success=True, message=f"File deleted: {filename}")
        except Exception as e:
            return DeleteFileResponse(success=False, message=f"Delete failed: {e}")
    
    def _is_safe_filename(self, filename: str) -> bool:
        """Check if filename is safe (no directory traversal)."""
        if not filename or filename.startswith(".") or ".." in filename:
            return False
        if "/" in filename or "\\" in filename:
            return False
        return filename.upper() not in {"CON", "PRN", "AUX", "NUL"}
    
    def _matches_pattern(self, filename: str, pattern: str | None) -> bool:
        """Check if filename matches pattern."""
        if not pattern:
            return True
        import fnmatch
        return fnmatch.fnmatch(filename.lower(), pattern.lower())
    
    async def _get_file_info(self, file_path: Path) -> FileInfo:
        """Get file information."""
        stat_info = file_path.stat()
        
        # Calculate checksum for files < 10MB
        checksum = ""
        if file_path.is_file() and stat_info.st_size < 10 * 1024 * 1024:
            try:
                hash_md5 = hashlib.md5()
                with open(file_path, "rb") as f:
                    for chunk in iter(lambda: f.read(4096), b""):
                        hash_md5.update(chunk)
                checksum = hash_md5.hexdigest()
            except Exception:
                pass
        
        return FileInfo(
            name=file_path.name,
            path=str(file_path.relative_to(self.storage_dir)),
            size=stat_info.st_size,
            modified_time=int(stat_info.st_mtime),
            is_directory=file_path.is_dir(),
            permissions=oct(stat_info.st_mode)[-3:],
            checksum=checksum
        )


async def create_server(storage_dir: str = "./storage"):
    """Create file transfer server."""
    config = ServerConfig(
        transport=TransportConfig(host="localhost", port=50051),
        max_workers=10
    )
    server = RPCPluginServer(config)
    server.add_service(FileTransferServicer(storage_dir))
    return server

if __name__ == "__main__":
    async def main():
        server = await create_server()
        try:
            await server.start()
            while True:
                await asyncio.sleep(1)
        except KeyboardInterrupt:
            pass
        finally:
            await server.stop()
    
    asyncio.run(main())
```

## Client Implementation

**file_transfer_client.py**
```python
import asyncio
import hashlib
import time
from pathlib import Path
from typing import Callable, AsyncIterator
import grpc

from file_transfer_pb2 import *
from file_transfer_pb2_grpc import FileTransferServiceStub

class FileTransferClient:
    """File transfer client implementation."""
    
    def __init__(self, host: str = "localhost", port: int = 50051):
        self.channel = grpc.aio.insecure_channel(f"{host}:{port}")
        self.stub = FileTransferServiceStub(self.channel)
        self.chunk_size = 1024 * 1024  # 1MB chunks
    
    async def upload_file(
        self, 
        local_path: str, 
        remote_filename: str | None = None,
        progress_callback: Callable[[int, int], None] | None = None
    ) -> bool:
        """Upload file to server."""
        local_file = Path(local_path)
        if not local_file.exists() or not local_file.is_file():
            return False
        
        remote_filename = remote_filename or local_file.name
        file_size = local_file.stat().st_size
        
        async def chunk_generator() -> AsyncIterator[FileChunk]:
            with open(local_file, "rb") as f:
                offset = 0
                while True:
                    data = f.read(self.chunk_size)
                    if not data:
                        break
                    
                    yield FileChunk(
                        filename=remote_filename,
                        offset=offset,
                        data=data,
                        total_size=file_size,
                        checksum=hashlib.md5(data).hexdigest()
                    )
                    
                    offset += len(data)
                    if progress_callback:
                        progress_callback(offset, file_size)
        
        try:
            response = await self.stub.UploadFile(chunk_generator())
            return response.success
        except grpc.RpcError:
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
        
        request = FileDownloadRequest(
            filename=remote_filename,
            start_offset=start_offset,
            max_chunk_size=self.chunk_size
        )
        
        try:
            local_file.parent.mkdir(parents=True, exist_ok=True)
            
            mode = "ab" if resume and start_offset > 0 else "wb"
            total_downloaded = start_offset
            total_size = 0
            
            with open(local_file, mode) as f:
                async for chunk in self.stub.DownloadFile(request):
                    if total_size == 0:
                        total_size = chunk.total_size
                    
                    # Verify chunk integrity
                    if hashlib.md5(chunk.data).hexdigest() != chunk.checksum:
                        return False
                    if chunk.offset != total_downloaded:
                        return False
                    
                    f.write(chunk.data)
                    total_downloaded += len(chunk.data)
                    
                    if progress_callback:
                        progress_callback(total_downloaded, total_size)
            
            return True
        
        except (grpc.RpcError, Exception):
            return False
    
    async def list_files(self, directory: str = ".", recursive: bool = False, pattern: str = "*") -> list:
        """List files on server."""
        request = ListFilesRequest(directory=directory, recursive=recursive, pattern=pattern)
        
        try:
            response = await self.stub.ListFiles(request)
            return [{
                'name': f.name, 'path': f.path, 'size': f.size,
                'modified': time.ctime(f.modified_time), 'is_directory': f.is_directory,
                'permissions': f.permissions, 'checksum': f.checksum
            } for f in response.files]
        except grpc.RpcError:
            return []
    
    async def get_file_info(self, filename: str) -> dict | None:
        """Get file information."""
        try:
            response = await self.stub.GetFileInfo(FileInfoRequest(filename=filename))
            if not response.exists:
                return None
            
            f = response.file_info
            return {
                'name': f.name, 'path': f.path, 'size': f.size,
                'modified': time.ctime(f.modified_time), 'is_directory': f.is_directory,
                'permissions': f.permissions, 'checksum': f.checksum
            }
        except grpc.RpcError:
            return None
    
    async def delete_file(self, filename: str) -> bool:
        """Delete file on server."""
        try:
            response = await self.stub.DeleteFile(DeleteFileRequest(filename=filename))
            return response.success
        except grpc.RpcError:
            return False
    
    async def close(self):
        """Close client connection."""
        await self.channel.close()


def progress_bar(current: int, total: int, width: int = 50):
    """Display progress bar."""
    percent = (current / total) * 100
    filled = int(width * current // total)
    bar = '█' * filled + '-' * (width - filled)
    print(f'\r|{bar}| {percent:.1f}% ({current}/{total} bytes)', end='', flush=True)


if __name__ == "__main__":
    async def demo():
        client = FileTransferClient()
        try:
            # Create test file
            test_file = Path("test.txt")
            test_file.write_text("Test data\n" * 1000)
            
            # Upload, list, download, verify
            await client.upload_file(str(test_file), "test.txt", progress_bar)
            files = await client.list_files()
            print(f"\nFiles: {[f['name'] for f in files]}")
            
            await client.download_file("test.txt", "downloaded.txt", progress_callback=progress_bar)
            print(f"\nVerified: {test_file.stat().st_size == Path('downloaded.txt').stat().st_size}")
            
            # Cleanup
            test_file.unlink()
            Path("downloaded.txt").unlink()
        finally:
            await client.close()
    
    asyncio.run(demo())
```

## Command Line Interface

**file_cli.py**
```python
import asyncio
import argparse
import sys
from file_transfer_client import FileTransferClient, progress_bar

async def main():
    parser = argparse.ArgumentParser(description="File Transfer Client")
    parser.add_argument("--host", default="localhost")
    parser.add_argument("--port", type=int, default=50051)
    
    subparsers = parser.add_subparsers(dest="command")
    
    # Upload
    upload = subparsers.add_parser("upload")
    upload.add_argument("local_file")
    upload.add_argument("--remote-name")
    
    # Download
    download = subparsers.add_parser("download")
    download.add_argument("remote_file")
    download.add_argument("local_file")
    download.add_argument("--resume", action="store_true")
    
    # List
    list_cmd = subparsers.add_parser("list")
    list_cmd.add_argument("--directory", default=".")
    list_cmd.add_argument("--recursive", action="store_true")
    
    # Info
    info = subparsers.add_parser("info")
    info.add_argument("filename")
    
    # Delete
    delete = subparsers.add_parser("delete")
    delete.add_argument("filename")
    
    args = parser.parse_args()
    if not args.command:
        parser.print_help()
        return
    
    client = FileTransferClient(args.host, args.port)
    try:
        if args.command == "upload":
            success = await client.upload_file(args.local_file, args.remote_name, progress_bar)
            sys.exit(0 if success else 1)
        elif args.command == "download":
            success = await client.download_file(args.remote_file, args.local_file, args.resume, progress_bar)
            sys.exit(0 if success else 1)
        elif args.command == "list":
            files = await client.list_files(args.directory, args.recursive)
            for f in files:
                print(f"{'DIR' if f['is_directory'] else 'FILE'} {f['size']:>10} {f['name']}")
        elif args.command == "info":
            info = await client.get_file_info(args.filename)
            if info:
                print(f"Name: {info['name']}\nSize: {info['size']}\nModified: {info['modified']}")
            else:
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

### Start Server
```bash
python file_transfer_service.py
```

### CLI Usage
```bash
# Upload/download files
python file_cli.py upload document.pdf --remote-name shared_doc.pdf
python file_cli.py download shared_doc.pdf ./downloads/document.pdf
python file_cli.py download large_file.zip ./downloads/large_file.zip --resume

# File operations
python file_cli.py list --directory uploads --recursive
python file_cli.py info shared_doc.pdf
python file_cli.py delete old_file.txt
```

### Programmatic Usage
```python
client = FileTransferClient()

# Upload with progress
await client.upload_file(
    "video.mp4",
    progress_callback=lambda c, t: print(f"Upload: {c/t*100:.1f}%")
)

# Download with resume
await client.download_file("backup.zip", "./backup.zip", resume=True)

await client.close()
```

## Key Features

- **Streaming transfers** with chunked data handling
- **Checksum verification** for data integrity
- **Resume capability** for interrupted transfers
- **Progress tracking** with real-time callbacks
- **Security validation** preventing path traversal
- **Error handling** with comprehensive exception management
- **CLI interface** for command-line operations
- **Metadata support** for file information and directory listing

This implementation provides a production-ready foundation for file sharing services with streaming RPC capabilities.
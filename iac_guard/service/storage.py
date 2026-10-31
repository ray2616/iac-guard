import hashlib
from pathlib import Path

from .config import settings


class Storage:
    def __init__(self):
        self.cfg = settings()
        self.client = None
        if self.cfg.storage_backend == "s3":
            import boto3

            if not self.cfg.s3_bucket:
                raise ValueError("S3_BUCKET is required for S3 storage")
            self.client = boto3.client("s3")
        elif self.cfg.storage_backend != "local":
            raise ValueError("Unknown storage backend")

    def put(self, data: bytes) -> str:
        key = "objects/" + hashlib.sha256(data).hexdigest()
        if self.client:
            self.client.put_object(
                Bucket=self.cfg.s3_bucket,
                Key=self.cfg.s3_prefix + key,
                Body=data,
                ServerSideEncryption="AES256",
            )
        else:
            target = self._path(key)
            target.parent.mkdir(parents=True, exist_ok=True)
            # Content-addressed objects are immutable; atomic replacement writes identical bytes.
            from uuid import uuid4

            temporary = target.with_suffix("." + uuid4().hex + ".tmp")
            temporary.write_bytes(data)
            temporary.replace(target)
        return key

    def get(self, key: str) -> bytes:
        self._validate(key)
        if self.client:
            return self.client.get_object(Bucket=self.cfg.s3_bucket, Key=self.cfg.s3_prefix + key)[
                "Body"
            ].read()
        return self._path(key).read_bytes()

    @staticmethod
    def _validate(key):
        import re

        if not re.fullmatch(r"objects/[0-9a-f]{64}", key):
            raise ValueError("Invalid object key")

    def _path(self, key):
        self._validate(key)
        return Path(self.cfg.storage_path).resolve() / key

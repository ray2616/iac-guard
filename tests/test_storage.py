import hashlib

from iac_guard.service.config import settings
from iac_guard.service.storage import Storage


def test_local_content_addressed_storage(tmp_path, monkeypatch):
    monkeypatch.setenv("STORAGE_BACKEND", "local")
    monkeypatch.setenv("STORAGE_PATH", str(tmp_path))
    settings.cache_clear()
    store = Storage()
    key = store.put(b"original")
    assert key.endswith(hashlib.sha256(b"original").hexdigest())
    assert store.put(b"original") == key
    assert store.get(key) == b"original"
    settings.cache_clear()


def test_s3_uses_private_prefix_and_encryption(monkeypatch):
    import io

    import boto3

    objects = {}
    calls = []

    class Client:
        def put_object(self, **kwargs):
            calls.append(kwargs)
            objects[kwargs["Key"]] = kwargs["Body"]

        def get_object(self, **kwargs):
            return {"Body": io.BytesIO(objects[kwargs["Key"]])}

    monkeypatch.setattr(boto3, "client", lambda _: Client())
    monkeypatch.setenv("STORAGE_BACKEND", "s3")
    monkeypatch.setenv("S3_BUCKET", "private-test-bucket")
    settings.cache_clear()
    store = Storage()
    key = store.put(b"private snapshot")
    assert store.get(key) == b"private snapshot"
    assert calls[0]["ServerSideEncryption"] == "AES256"
    assert calls[0]["Key"].startswith("iac-guard/objects/")
    assert "ACL" not in calls[0]
    settings.cache_clear()

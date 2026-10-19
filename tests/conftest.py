import os
import tempfile

# Point the app at a throwaway database before anything imports `app`.
os.environ["DATABASE_PATH"] = os.path.join(tempfile.mkdtemp(), "test.db")
os.environ["JWT_SECRET"] = "test-secret"

import pytest  # noqa: E402

from app import create_app  # noqa: E402


@pytest.fixture()
def client():
    app = create_app()
    app.testing = True
    with app.test_client() as test_client:
        yield test_client

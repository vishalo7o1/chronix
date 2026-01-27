# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Tyrrell Brewster

"""
Tests for Notes Export and Attachment features.
"""

import io
import os
import sys
import tempfile
import zipfile

# Add src to path for testing
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

import pytest
from fastapi.testclient import TestClient

# Set up test environment
os.environ["CHRONIX_SESSION_SECRET"] = "test-secret-key-for-testing-only-32chars"
os.environ["CHRONIX_DEBUG"] = "true"

from chronix.server import app, SessionLocal, engine
from chronix.models import Base, User, Engagement, NotePage, NoteAttachment
from chronix.security import hash_password, session_store, UserRole


@pytest.fixture(scope="module")
def test_db():
    """Create a test database."""
    # Use a temporary database
    import tempfile
    from chronix.models import init_db
    from sqlalchemy.orm import sessionmaker
    
    with tempfile.NamedTemporaryFile(suffix='.db', delete=False) as f:
        db_path = f.name
    
    test_engine = init_db(db_path)
    TestSession = sessionmaker(bind=test_engine)
    
    # Create test data
    db = TestSession()
    
    # Create admin user
    admin = User(
        id="test-user-id",
        username="admin",
        password_hash=hash_password("testpass"),
        display_name="Test Admin",
        role=UserRole.ADMIN,
    )
    db.add(admin)
    
    # Create workspace
    workspace = Engagement(
        id="test-workspace-id",
        name="Test Workspace",
        description="Test workspace for unit tests",
    )
    db.add(workspace)
    
    # Create note pages
    note1 = NotePage(
        id="test-note-1",
        engagement_id="test-workspace-id",
        title="Reconnaissance Notes",
        content="# Reconnaissance\n\nThis is test content with **markdown**.\n\n- Item 1\n- Item 2",
        order_index=0,
    )
    note2 = NotePage(
        id="test-note-2",
        engagement_id="test-workspace-id",
        title="Exploitation Notes",
        content="# Exploitation\n\n```bash\nnmap -sV target.local\n```\n",
        order_index=1,
    )
    db.add(note1)
    db.add(note2)
    
    db.commit()
    db.close()
    
    yield test_engine, db_path
    
    # Cleanup
    os.unlink(db_path)


@pytest.fixture
def client(test_db):
    """Create a test client with authenticated session."""
    from chronix import server
    
    test_engine, db_path = test_db
    server.engine = test_engine
    server.SessionLocal = lambda: server.sessionmaker(bind=test_engine)()
    
    # Override database path
    os.environ["CHRONIX_DB_PATH"] = db_path
    
    client = TestClient(app)
    
    # Create authenticated session
    session_id = session_store.create(
        user_id="test-user-id",
        username="admin",
        role=UserRole.ADMIN,
        ip_address="127.0.0.1",
        user_agent="test-client",
        engagement_ids=None,  # Admin has access to all
    )
    
    # Set session cookie
    client.cookies.set("chronix_session", session_id)
    
    yield client
    
    # Cleanup session
    session_store.delete(session_id)


class TestSlugify:
    """Test the slugify function."""
    
    def test_basic_slugify(self):
        from chronix.server import slugify
        
        assert slugify("Hello World") == "hello-world"
        assert slugify("Recon & Enumeration") == "recon--enumeration"
        assert slugify("Test_Page_123") == "test-page-123"
        assert slugify("   spaces   ") == "spaces"
        assert slugify("") == "untitled"


class TestSanitizeFilename:
    """Test filename sanitization."""
    
    def test_sanitize_filename(self):
        from chronix.server import sanitize_filename
        
        assert sanitize_filename("image.png") == "image.png"
        assert sanitize_filename("../../../etc/passwd") == "passwd"
        assert sanitize_filename("file\x00name.png") == "filename.png"
        assert sanitize_filename("file<>:\"/\\|?*.png") == "file.png"


class TestExportFilename:
    """Test export filename generation."""
    
    def test_generate_export_filename(self):
        from chronix.server import generate_export_filename
        
        filename = generate_export_filename("Recon Notes", "abc12345-6789")
        assert filename.startswith("recon-notes__note_")
        assert filename.endswith(".md")
        assert "abc12345" in filename


class TestYamlFrontmatter:
    """Test YAML frontmatter generation."""
    
    def test_generate_frontmatter(self):
        from chronix.server import generate_yaml_frontmatter
        from chronix.models import NotePage, Engagement
        from datetime import datetime
        
        page = NotePage(
            id="test-id",
            title="Test Page",
            created_at=datetime(2024, 1, 15, 10, 30, 0),
            updated_at=datetime(2024, 1, 15, 12, 0, 0),
        )
        eng = Engagement(id="eng-id", name="Test Engagement")
        
        frontmatter = generate_yaml_frontmatter(page, eng)
        
        assert "---" in frontmatter
        assert 'title: "Test Page"' in frontmatter
        assert 'note_id: "test-id"' in frontmatter
        assert 'engagement_id: "eng-id"' in frontmatter


class TestRewriteAttachmentPaths:
    """Test attachment path rewriting."""
    
    def test_rewrite_paths(self):
        from chronix.server import rewrite_attachment_paths
        from chronix.models import NoteAttachment
        
        att = NoteAttachment(
            stored_filename="abc123_20240115_a1b2c3d4.png",
        )
        
        content = "![image](/api/attachments/abc123_20240115_a1b2c3d4.png)"
        rewritten = rewrite_attachment_paths(content, [att])
        
        assert "./attachments/abc123_20240115_a1b2c3d4.png" in rewritten
        assert "/api/attachments/" not in rewritten


class TestExportEndpoints:
    """Test export API endpoints."""
    
    def test_export_single_note(self, client):
        """Test exporting a single note as markdown."""
        response = client.get(
            "/api/engagements/test-workspace-id/note-pages/test-note-1/export"
        )
        
        assert response.status_code == 200
        assert response.headers["content-type"].startswith("text/markdown")
        
        content = response.text
        assert "---" in content  # Frontmatter
        assert "Reconnaissance" in content
        assert "test-note-1" in content
    
    def test_export_single_note_no_frontmatter(self, client):
        """Test exporting without frontmatter."""
        response = client.get(
            "/api/engagements/test-workspace-id/note-pages/test-note-1/export?include_frontmatter=false"
        )
        
        assert response.status_code == 200
        content = response.text
        
        # Should not have YAML frontmatter
        assert not content.startswith("---")
        assert "# Reconnaissance" in content
    
    def test_export_all_notes_zip(self, client):
        """Test exporting all notes as zip."""
        response = client.get(
            "/api/engagements/test-workspace-id/notes/export"
        )
        
        assert response.status_code == 200
        assert response.headers["content-type"] == "application/zip"
        
        # Parse the zip file
        zip_buffer = io.BytesIO(response.content)
        with zipfile.ZipFile(zip_buffer, 'r') as zf:
            names = zf.namelist()
            
            # Should have markdown files for both notes
            md_files = [n for n in names if n.endswith('.md')]
            assert len(md_files) >= 2
            
            # Check content of first note
            for name in md_files:
                content = zf.read(name).decode('utf-8')
                assert "---" in content  # Has frontmatter


class TestAttachmentEndpoints:
    """Test attachment upload and serving endpoints."""
    
    def test_upload_png_attachment(self, client):
        """Test uploading a PNG image."""
        # Create a minimal valid PNG (1x1 transparent pixel)
        png_data = bytes([
            0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A,  # PNG signature
            0x00, 0x00, 0x00, 0x0D, 0x49, 0x48, 0x44, 0x52,  # IHDR chunk
            0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01,  # 1x1
            0x08, 0x06, 0x00, 0x00, 0x00, 0x1F, 0x15, 0xC4,
            0x89, 0x00, 0x00, 0x00, 0x0A, 0x49, 0x44, 0x41,  # IDAT chunk
            0x54, 0x78, 0x9C, 0x63, 0x00, 0x01, 0x00, 0x00,
            0x05, 0x00, 0x01, 0x0D, 0x0A, 0x2D, 0xB4, 0x00,
            0x00, 0x00, 0x00, 0x49, 0x45, 0x4E, 0x44, 0xAE,  # IEND chunk
            0x42, 0x60, 0x82,
        ])
        
        response = client.post(
            "/api/engagements/test-workspace-id/note-pages/test-note-1/attachments",
            files={"file": ("test.png", io.BytesIO(png_data), "image/png")},
        )
        
        assert response.status_code == 200
        data = response.json()
        
        assert data["filename"] == "test.png"
        assert data["mime_type"] == "image/png"
        assert data["url"].startswith("/api/attachments/")
        assert data["note_page_id"] == "test-note-1"
    
    def test_reject_invalid_mime_type(self, client):
        """Test rejection of non-image files."""
        response = client.post(
            "/api/engagements/test-workspace-id/note-pages/test-note-1/attachments",
            files={"file": ("test.txt", io.BytesIO(b"not an image"), "text/plain")},
        )
        
        assert response.status_code == 400
        assert "Invalid file type" in response.json()["detail"]
    
    def test_list_attachments(self, client):
        """Test listing attachments for a note page."""
        response = client.get(
            "/api/engagements/test-workspace-id/note-pages/test-note-1/attachments"
        )
        
        assert response.status_code == 200
        data = response.json()
        
        assert "attachments" in data
        assert "total" in data


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

"""Student Document Portal -- a DELIBERATELY VULNERABLE practice application.

!!! DO NOT DEPLOY. FOR LOCAL SECURITY TESTING ONLY. !!!

This tiny Flask app is the target that PatchProof scans, patches and verifies.
It contains exactly two intentional vulnerabilities:

  1. SQL injection in  GET /search                 (unsafe f-string SQL)
  2. IDOR              in  GET /documents/<doc_id>  (no ownership/permission check)

All data is synthetic and lives in a throwaway SQLite file created by the
test harness (see fixtures/seed/student_portal.sql). Authentication is a
simplified synthetic token sent in the X-User-Token header.
"""
import sqlite3

from flask import Flask, abort, g, jsonify, request


def create_app(config=None):
    app = Flask(__name__)
    app.config.update(config or {})

    def get_db():
        if "db" not in g:
            g.db = sqlite3.connect(app.config["DATABASE"])
            g.db.row_factory = sqlite3.Row
        return g.db

    @app.teardown_appcontext
    def close_db(_exc):
        db = g.pop("db", None)
        if db is not None:
            db.close()

    def query_one(sql, params=()):
        return get_db().execute(sql, params).fetchone()

    def get_current_user():
        token = request.headers.get("X-User-Token")
        if not token:
            return None
        return query_one("SELECT id, username, role FROM users WHERE api_token = ?", (token,))

    def can_view_document(user, doc):
        """Authorisation rule: public docs, own docs, or docs of an assigned student."""
        if doc["is_public"]:
            return True
        if user is None:
            return False
        if doc["owner_id"] == user["id"]:
            return True
        if user["role"] == "teacher":
            link = query_one(
                "SELECT 1 FROM teacher_students WHERE teacher_id = ? AND student_id = ?",
                (user["id"], doc["owner_id"]),
            )
            return link is not None
        return False

    @app.route("/health")
    def health():
        return jsonify({"status": "ok"})

    @app.route("/search")
    def search():
        term = request.args.get("q", "")
        sql = f"SELECT id, title FROM documents WHERE is_public = 1 AND title LIKE '%{term}%'"
        rows = get_db().execute(sql).fetchall()
        return jsonify([dict(r) for r in rows])

    @app.route("/documents/mine")
    def my_documents():
        user = get_current_user()
        if user is None:
            abort(401)
        rows = get_db().execute(
            "SELECT id, title, is_public FROM documents WHERE owner_id = ?", (user["id"],)
        ).fetchall()
        return jsonify([dict(r) for r in rows])

    @app.route("/documents/<int:doc_id>")
    def get_document(doc_id):
        user = get_current_user()
        doc = query_one("SELECT id, owner_id, title, body, is_public FROM documents WHERE id = ?", (doc_id,))
        if doc is None:
            abort(404)
        return jsonify(dict(doc))

    @app.route("/documents/<int:doc_id>/summary")
    def document_summary(doc_id):
        user = get_current_user()
        doc = query_one("SELECT id, owner_id, title, body, is_public FROM documents WHERE id = ?", (doc_id,))
        if doc is None:
            abort(404)
        if not can_view_document(user, doc):
            abort(403)
        return jsonify({"id": doc["id"], "title": doc["title"], "length": len(doc["body"])})

    return app

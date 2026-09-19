from secreview.diff import parse_diff

SAMPLE = """diff --git a/app/users.py b/app/users.py
index 1111111..2222222 100644
--- a/app/users.py
+++ b/app/users.py
@@ -10,1 +10,3 @@ def get_connection():
     return sqlite3.connect(DB_PATH)
+def find_user(username):
+    return username
diff --git a/vendor/lib.py b/vendor/lib.py
index 4444444..5555555 100644
--- a/vendor/lib.py
+++ b/vendor/lib.py
@@ -1,1 +1,2 @@
 x = 1
+y = 2
"""


def test_parses_added_lines() -> None:
    changed = parse_diff(SAMPLE)
    by_path = {c.path: c for c in changed}
    assert "app/users.py" in by_path
    # Two added lines in the app file.
    assert len(by_path["app/users.py"].added_lines) == 2


def test_ignore_paths_filters_globs() -> None:
    changed = parse_diff(SAMPLE, ignore_paths=["vendor/**", "**/vendor/**"])
    paths = {c.path for c in changed}
    assert "vendor/lib.py" not in paths
    assert "app/users.py" in paths

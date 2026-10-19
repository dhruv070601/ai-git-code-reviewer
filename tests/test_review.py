import unittest
from reviewer.review import review_diff, render_markdown
class GitReviewTests(unittest.TestCase):
    def test_plain_change_is_low(self):
        r=review_diff('diff --git a/app.py b/app.py\n+++ b/app.py\n+print("hello")\n')
        self.assertEqual(r["risk_level"],"LOW"); self.assertEqual(r["findings"],[])
    def test_destructive_sql_is_high(self):
        r=review_diff("diff --git a/db.sql b/db.sql\n+++ b/db.sql\n+DROP TABLE customers;\n")
        self.assertEqual(r["risk_level"],"HIGH"); self.assertTrue(r["findings"])
    def test_world_writable_permissions(self):
        self.assertEqual(review_diff("diff --git a/deploy.sh b/deploy.sh\n+++ b/deploy.sh\n+chmod 777 /opt/app\n")["risk_level"],"HIGH")
    def test_credentials_redacted(self):
        r=review_diff("diff --git a/config.py b/config.py\n+++ b/config.py\n+api_key = supersecretvalue123\n")
        self.assertNotIn("supersecretvalue123",str(r))
    def test_change_counts(self):
        r=review_diff("diff --git a/a.py b/a.py\n+++ b/a.py\n+added\n-removed\n")
        self.assertEqual(r["files_changed"],["a.py"]); self.assertEqual(r["additions"],1); self.assertEqual(r["deletions"],1)
    def test_markdown_report(self): self.assertIn("Recommendations",render_markdown(review_diff("")))
if __name__=="__main__": unittest.main()

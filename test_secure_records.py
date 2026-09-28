import sys, tempfile, unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
import secure_records as sr


class T(unittest.TestCase):
    def setUp(self):
        self._d = tempfile.TemporaryDirectory(); self.t = Path(self._d.name)
        self.key = self.t / "k.key"; sr.generate_key(self.key)
        self.f = self.t / "rec.csv"; self.f.write_text("id,name\n1,Sample\n")
        self.m = self.t / "m.json"
    def tearDown(self): self._d.cleanup()

    def test_roundtrip(self):
        sr.encrypt_file(self.f, self.t / "rec.enc", self.key, self.m)
        self.assertNotEqual((self.t / "rec.enc").read_bytes(), self.f.read_bytes())
        sr.decrypt_file(self.t / "rec.enc", self.t / "out.csv", self.key)
        self.assertTrue(sr.verify_roundtrip(self.f, self.t / "out.csv"))

    def test_file_change_detected(self):
        sr.record_hash(self.f, self.m); self.assertTrue(sr.verify_hash(self.f, self.m))
        self.f.write_text("id,name\n1,Changed\n"); self.assertFalse(sr.verify_hash(self.f, self.m))

    def test_tampered_ciphertext_rejected(self):
        sr.encrypt_file(self.f, self.t / "e", self.key, self.m)
        b = bytearray((self.t / "e").read_bytes()); b[-1] ^= 1; (self.t / "e").write_bytes(bytes(b))
        with self.assertRaises(sr.SecureRecordsError): sr.decrypt_file(self.t / "e", self.t / "o", self.key)

    def test_wrong_key(self):
        sr.encrypt_file(self.f, self.t / "e", self.key, self.m)
        k2 = self.t / "k2"; sr.generate_key(k2)
        with self.assertRaises(sr.SecureRecordsError): sr.decrypt_file(self.t / "e", self.t / "o", k2)

    def test_missing_and_invalid_inputs_do_not_crash(self):
        k, t = str(self.key), self.t
        self.assertEqual(sr.main(["--key", k, "encrypt", str(t / "nope"), str(t / "x")]), 1)
        (t / "junk").write_bytes(b"hello")
        self.assertEqual(sr.main(["--key", k, "decrypt", str(t / "junk"), str(t / "x")]), 1)
        self.assertEqual(sr.main(["--key", str(t / "nokey"), "encrypt", str(self.f), str(t / "x")]), 1)
        (t / "empty").write_bytes(b"")
        self.assertEqual(sr.main(["--key", k, "encrypt", str(t / "empty"), str(t / "x")]), 1)
        self.assertEqual(sr.main(["--key", k, "encrypt", str(t), str(t / "x")]), 1)  # directory


if __name__ == "__main__":
    unittest.main(verbosity=2)

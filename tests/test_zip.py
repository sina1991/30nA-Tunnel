"""Exercise the nano password handoff with an actual encrypted archive."""
from pathlib import Path
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

PROJECT = Path(__file__).resolve().parents[1]
SEVEN = os.environ.get("P7ZIP_BIN") or shutil.which("7z") or shutil.which("7zz")


@unittest.skipUnless(SEVEN, "Set P7ZIP_BIN or install p7zip-full")
class ZipTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name)
        self.source=self.root/"source"
        self.source.mkdir()
        subprocess.run(["ssh-keygen","-qt","ed25519","-N","","-f",str(self.source/"30na_windows")],check=True)
        self.archive=self.root/"backup.zip"
        subprocess.run([SEVEN,"a","-tzip","-mem=AES256","-ptest password",str(self.archive),
                        "30na_windows","30na_windows.pub"],cwd=self.source,check=True,stdout=subprocess.DEVNULL)
        self.home=self.root/"home"
        self.home.mkdir()
        self.password=self.root/"password"
        self.password.write_text("test password\n")
        self.bin=self.root/"bin"
        self.bin.mkdir()
        wrapper=self.bin/"7z"
        wrapper.write_text("#!/bin/sh\nexec "+shlex_quote(SEVEN)+' "$@"\n')
        wrapper.chmod(0o700)

    def restore(self,success=True):
        env=dict(os.environ,HOME=str(self.home),STM_PASSWORD_FILE=str(self.password),
                 PATH=str(self.bin)+":"+os.environ["PATH"],LC_ALL="C.UTF-8")
        result=subprocess.run(["bash",str(PROJECT/"lib/restore-key.sh"),str(self.archive)],
                              env=env,capture_output=True,timeout=20)
        if success:
            self.assertEqual(result.returncode,0,result.stderr.decode()+result.stdout.decode())
        else:
            self.assertNotEqual(result.returncode,0)
        self.assertNotIn("test password",result.stdout.decode())
        return result

    def test_restore_once_then_repeat(self):
        self.restore()
        private=self.home/".ssh/30na_windows"
        original=private.read_bytes()
        self.restore()
        self.assertEqual(private.read_bytes(),original)
        self.assertEqual(private.stat().st_mode&0o777,0o600)

    def test_wrong_password_fails_without_waiting_for_input(self):
        self.password.write_text("incorrect\n")
        self.restore(False)
        self.assertFalse((self.home/".ssh/30na_windows").exists())

    def test_conflicting_key_is_preserved(self):
        self.restore()
        private=self.home/".ssh/30na_windows"
        private.unlink()
        private.with_suffix(".pub").unlink()
        subprocess.run(["ssh-keygen","-qt","ed25519","-N","","-f",str(private)],check=True)
        original=private.read_bytes()
        self.restore(False)
        self.assertEqual(private.read_bytes(),original)

    def test_incomplete_key_is_preserved(self):
        self.restore()
        private=self.home/".ssh/30na_windows"
        original=private.read_bytes()
        private.with_suffix(".pub").unlink()
        self.restore(False)
        self.assertEqual(private.read_bytes(),original)


def shlex_quote(value):
    import shlex
    return shlex.quote(value)


if __name__=="__main__":
    unittest.main()

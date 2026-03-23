import pytest, sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from phantom.classifier import HoneypotClassifier, HoneypotPlatform
from phantom.topology import TopologyMapper, DeceptionStrategy, PortRecord
from phantom.counter import CounterEngine, HoneypotPlatform as HP
from phantom.engine import PhantomEngine
from phantom.topology import TopologyReport

class TestClassifier:
    def setup_method(self): self.clf = HoneypotClassifier()

    def test_cowrie_default(self):
        r = self.clf.classify(b"SSH-2.0-OpenSSH_6.0p1 Debian-4+deb7u2\r\n", 22)
        assert r.platform == HoneypotPlatform.COWRIE and r.confidence >= 0.90

    def test_kippo_banner(self):
        r = self.clf.classify(b"SSH-2.0-OpenSSH_5.1p1 Debian-5\r\n", 22)
        assert r.platform == HoneypotPlatform.KIPPO and r.confidence >= 0.90

    def test_thinkst_token(self):
        r = self.clf.classify(b"<script src='https://canarytokens.com/x'>", 80)
        assert r.platform == HoneypotPlatform.THINKST and r.confidence >= 0.95

    def test_opencanary_ssh(self):
        r = self.clf.classify(b"SSH-2.0-OpenSSH_5.9p1 Debian-5ubuntu1.1\r\n", 22)
        assert r.platform == HoneypotPlatform.OPENCANARY

    def test_dionaea_ftp(self):
        r = self.clf.classify(b"220 DiskStation FTP server ready.\r\n", 21)
        assert r.platform == HoneypotPlatform.DIONAEA and r.confidence >= 0.85

    def test_honeyd_ftp(self):
        r = self.clf.classify(b"220 server FTP server (Version wu-2.6.2) ready.\r\n", 21)
        assert r.platform == HoneypotPlatform.HONEYD

    def test_ssh_v1_suspicious(self):
        r = self.clf.classify(b"SSH-1.99-OpenSSH_4.3\r\n", 22)
        assert r.platform == HoneypotPlatform.UNKNOWN_FAKE and r.confidence >= 0.65

    def test_empty_banner_unknown(self):
        r = self.clf.classify(b"", 9999)
        assert r.platform == HoneypotPlatform.UNKNOWN_FAKE and r.confidence <= 0.50

    def test_batch(self):
        inputs = [(22,"tcp",b"SSH-2.0-OpenSSH_6.0p1 Debian-4+deb7u2\r\n",None),
                  (21,"tcp",b"220 DiskStation FTP server ready.\r\n",None)]
        results = self.clf.classify_batch(inputs)
        assert results[0].platform == HoneypotPlatform.COWRIE
        assert results[1].platform == HoneypotPlatform.DIONAEA

    def test_risk_label(self):
        r = self.clf.classify(b"SSH-2.0-OpenSSH_6.0p1 Debian-4+deb7u2\r\n", 22)
        assert "DECOY" in r.risk_label

class TestTopology:
    def setup_method(self): self.m = TopologyMapper()

    def _records(self, real, fake, timing=None):
        return ([PortRecord(p,"tcp",True,b"real",timing) for p in real] +
                [PortRecord(p,"tcp",False,b"",timing) for p in fake])

    def test_all_ports_open(self):
        r = self.m.analyze("10.0.0.1", self._records([22], list(range(100,1000))))
        assert r.strategy == DeceptionStrategy.ALL_PORTS_OPEN

    def test_sparse(self):
        r = self.m.analyze("10.0.0.1", self._records(list(range(80,100)), [9999]))
        assert r.strategy == DeceptionStrategy.SPARSE

    def test_tarpit(self):
        r = self.m.analyze("10.0.0.1", self._records([22],[80,443],timing=5500.0))
        assert r.tarpit_suspected and r.strategy == DeceptionStrategy.TARPIT

    def test_empty(self):
        r = self.m.analyze("10.0.0.1", [])
        assert r.strategy == DeceptionStrategy.UNKNOWN and r.total_scanned == 0

    def test_threat_level_high(self):
        r = self.m.analyze("10.0.0.1", self._records([22], list(range(100,1000))))
        assert "HIGH" in r.threat_level

class TestEngine:
    def setup_method(self): self.e = PhantomEngine()

    def test_full_pipeline(self):
        results = [(True,443,"tcp",b"OpenSSH_8.4p1",None),
                   (False,22,"tcp",b"SSH-2.0-OpenSSH_6.0p1 Debian-4+deb7u2\r\n",None)]
        r = self.e.analyze("10.0.0.1", results)
        assert r.topology.real_count == 1
        assert 443 in r.playbook.prioritize_ports
        assert 22 in r.playbook.avoid_ports

    def test_parse_output(self):
        raw = "[REAL] 22/tcp open ssh (via passive/NULL) → SSH-2.0-OpenSSH_8.4p1\n[FAKE] 80/tcp open unknown (via none) →"
        results = PhantomEngine.parse_decoy_hunter_output(raw, "10.0.0.1")
        assert len(results) == 2
        assert results[0][0] is True
        assert results[1][0] is False

    def test_to_dict(self):
        r = self.e.analyze("10.0.0.1", [(True,22,"tcp",b"SSH_8.4",None)])
        d = r.to_dict()
        assert all(k in d for k in ["host","topology","classifications","playbook"])

    def test_empty(self):
        r = self.e.analyze("10.0.0.1", [])
        assert r.topology.total_scanned == 0
        assert r.playbook.lanimals_risk_score == 0.0

    def test_scan_time(self):
        r = self.e.analyze("10.0.0.1", [(True,22,"tcp",b"x",None)])
        assert r.scan_time_s > 0

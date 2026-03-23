import re, logging
from dataclasses import dataclass, asdict
from typing import Optional
from enum import Enum

logger = logging.getLogger("phantom.classifier")

class HoneypotPlatform(str, Enum):
    COWRIE        = "Cowrie"
    OPENCANARY    = "OpenCanary"
    THINKST       = "Thinkst Canary"
    HONEYD        = "HoneyD"
    GLUTTON       = "Glutton"
    S0I37_DEFENCE = "s0i37 Defence"
    KIPPO         = "Kippo"
    DIONAEA       = "Dionaea"
    UNKNOWN_FAKE  = "Unknown Fake Responder"
    NOT_FAKE      = "Real Service"

@dataclass
class ClassifierSignature:
    platform: HoneypotPlatform
    name: str
    protocol: str
    pattern: re.Pattern
    confidence: float
    notes: str = ""

@dataclass
class ClassificationResult:
    platform: HoneypotPlatform
    confidence: float
    matched_signature: str
    protocol_hint: str
    port: int
    banner_excerpt: str
    timing_ms: Optional[float] = None
    notes: str = ""

    def to_dict(self):
        d = asdict(self)
        d["platform"] = self.platform.value
        return d

    @property
    def risk_label(self):
        if self.confidence >= 0.85: return "HIGH-CONFIDENCE DECOY"
        elif self.confidence >= 0.60: return "LIKELY DECOY"
        elif self.confidence >= 0.35: return "POSSIBLE DECOY"
        else: return "UNCERTAIN"

_SIGNATURES = [
    ClassifierSignature(HoneypotPlatform.COWRIE, "cowrie-ssh-default", "ssh",
        re.compile(rb"SSH-2\.0-OpenSSH_6\.0p1 Debian-4\+deb7u2", re.I), 0.97,
        "Classic Cowrie default banner."),
    ClassifierSignature(HoneypotPlatform.COWRIE, "cowrie-ssh-variant", "ssh",
        re.compile(rb"SSH-2\.0-OpenSSH_5\.[0-9]", re.I), 0.80,
        "Old OpenSSH — common Cowrie config."),
    ClassifierSignature(HoneypotPlatform.COWRIE, "cowrie-telnet", "telnet",
        re.compile(rb"Ubuntu 12\.04|Ubuntu 14\.04.*login:", re.I|re.DOTALL), 0.88,
        "Cowrie Telnet emulates aged Ubuntu."),
    ClassifierSignature(HoneypotPlatform.KIPPO, "kippo-ssh-banner", "ssh",
        re.compile(rb"SSH-2\.0-OpenSSH_5\.1p1 Debian-5", re.I), 0.93,
        "Kippo default banner."),
    ClassifierSignature(HoneypotPlatform.KIPPO, "kippo-ssh-alt", "ssh",
        re.compile(rb"SSH-2\.0-OpenSSH_5\.3p1", re.I), 0.75,
        "Alt Kippo banner."),
    ClassifierSignature(HoneypotPlatform.OPENCANARY, "opencanary-ssh", "ssh",
        re.compile(rb"SSH-2\.0-OpenSSH_5\.9p1 Debian-5ubuntu1\.1", re.I), 0.90,
        "OpenCanary SSH default."),
    ClassifierSignature(HoneypotPlatform.OPENCANARY, "opencanary-ftp", "ftp",
        re.compile(rb"220.*FileZilla Server version 0\.[9]", re.I), 0.85,
        "OpenCanary FTP module."),
    ClassifierSignature(HoneypotPlatform.OPENCANARY, "opencanary-x-header", "http",
        re.compile(rb"X-Canary:", re.I), 0.97,
        "OpenCanary injects X-Canary header."),
    ClassifierSignature(HoneypotPlatform.THINKST, "thinkst-token-url", "http",
        re.compile(rb"canarytokens\.com|canarytokens\.org", re.I), 0.99,
        "Thinkst Canary token domain."),
    ClassifierSignature(HoneypotPlatform.THINKST, "thinkst-ssh-key-comment", "ssh",
        re.compile(rb"canary@[a-z0-9\-]+\.(canary|thinkst)", re.I), 0.96,
        "Thinkst SSH host key comment."),
    ClassifierSignature(HoneypotPlatform.HONEYD, "honeyd-smtp", "smtp",
        re.compile(rb"220 [a-z0-9\-]+ ESMTP Sendmail 8\.11\.[0-9]", re.I), 0.85,
        "HoneyD SMTP old Sendmail."),
    ClassifierSignature(HoneypotPlatform.HONEYD, "honeyd-ftp", "ftp",
        re.compile(rb"220 [a-z0-9\-]+ FTP server \(Version wu-2\.", re.I), 0.87,
        "HoneyD FTP wu-ftpd."),
    ClassifierSignature(HoneypotPlatform.DIONAEA, "dionaea-ftp", "ftp",
        re.compile(rb"220 DiskStation FTP server ready\.", re.I), 0.88,
        "Dionaea Synology impersonation."),
    ClassifierSignature(HoneypotPlatform.DIONAEA, "dionaea-smb", "smb",
        re.compile(rb"\xff\x53\x4d\x42\x72\x00\x00\x00\x00\x88", re.DOTALL), 0.82,
        "Dionaea SMB negotiate bytes."),
    ClassifierSignature(HoneypotPlatform.S0I37_DEFENCE, "s0i37-short-response", "generic",
        re.compile(rb"^.{1,16}$", re.DOTALL), 0.45,
        "s0i37 short/silent response. Low confidence alone."),
    ClassifierSignature(HoneypotPlatform.GLUTTON, "glutton-null-banner", "generic",
        re.compile(rb"^\x00{4,16}$", re.DOTALL), 0.55,
        "Glutton null-byte banner."),
    ClassifierSignature(HoneypotPlatform.UNKNOWN_FAKE, "generic-ssh-v1", "ssh",
        re.compile(rb"SSH-1[.\-][0-9]", re.I), 0.70,
        "SSHv1 is dead on modern networks."),
    ClassifierSignature(HoneypotPlatform.UNKNOWN_FAKE, "generic-honeypot-header", "http",
        re.compile(rb"X-Honeypot:|X-Deception:", re.I), 0.95,
        "Explicit honeypot header."),
    ClassifierSignature(HoneypotPlatform.UNKNOWN_FAKE, "generic-iis-old", "http",
        re.compile(rb"Server: Microsoft-IIS/[456]\.", re.I), 0.72,
        "IIS 4/5/6 extinct post-2015."),
    ClassifierSignature(HoneypotPlatform.UNKNOWN_FAKE, "generic-ftp-old", "ftp",
        re.compile(rb"220.*wu-2\.[456]|220.*ProFTPD 1\.[12]\.", re.I), 0.68,
        "Old FTP versions in honeypot templates."),
]

class HoneypotClassifier:
    def __init__(self, signatures=None):
        self.signatures = signatures if signatures is not None else _SIGNATURES

    def classify(self, banner: bytes, port: int, proto: str = "tcp",
                 timing_ms=None) -> ClassificationResult:
        best = None
        excerpt = banner[:120].decode("utf-8", errors="replace").strip()
        for sig in self.signatures:
            try:
                if sig.pattern.search(banner):
                    r = ClassificationResult(sig.platform, sig.confidence, sig.name,
                        sig.protocol, port, excerpt, timing_ms, sig.notes)
                    if best is None or sig.confidence > best.confidence:
                        best = r
            except Exception:
                pass
        if best:
            return best
        return ClassificationResult(HoneypotPlatform.UNKNOWN_FAKE, 0.30, "none",
            self._guess_protocol(port), port, excerpt, timing_ms,
            "No signature matched. Marked fake by Decoy-Hunter.")

    def classify_batch(self, fake_results):
        return [self.classify(b, p, pr, t) for p, pr, b, t in fake_results]

    @staticmethod
    def _guess_protocol(port):
        return {21:"ftp",22:"ssh",23:"telnet",25:"smtp",80:"http",110:"pop3",
                143:"imap",443:"http",445:"smb",3389:"rdp",8080:"http",8443:"http"
                }.get(port, "generic")

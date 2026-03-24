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
    TPOT          = "T-Pot"
    CONPOT        = "Conpot"
    ELASTICPOT    = "Elasticpot"
    MAILONEY      = "Mailoney"
    HONEYTRAP     = "Honeytrap"
    SHOCKPOT      = "Shockpot"
    WORDPOT       = "Wordpot"
    ADBHONEY      = "ADBHoney"
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
    # Cowrie
    ClassifierSignature(HoneypotPlatform.COWRIE, "cowrie-ssh-default", "ssh",
        re.compile(rb"SSH-2\.0-OpenSSH_6\.0p1 Debian-4\+deb7u2", re.I), 0.97,
        "Classic Cowrie default SSH banner."),
    ClassifierSignature(HoneypotPlatform.COWRIE, "cowrie-ssh-variant", "ssh",
        re.compile(rb"SSH-2\.0-OpenSSH_5\.[0-9]", re.I), 0.80,
        "Old OpenSSH common Cowrie config."),
    ClassifierSignature(HoneypotPlatform.COWRIE, "cowrie-telnet", "telnet",
        re.compile(rb"Ubuntu 12\.04|Ubuntu 14\.04.*login:", re.I|re.DOTALL), 0.88,
        "Cowrie Telnet emulates aged Ubuntu."),
    # Kippo
    ClassifierSignature(HoneypotPlatform.KIPPO, "kippo-ssh-banner", "ssh",
        re.compile(rb"SSH-2\.0-OpenSSH_5\.1p1 Debian-5", re.I), 0.93,
        "Kippo default SSH banner."),
    ClassifierSignature(HoneypotPlatform.KIPPO, "kippo-ssh-alt", "ssh",
        re.compile(rb"SSH-2\.0-OpenSSH_5\.3p1", re.I), 0.75,
        "Alt Kippo banner."),
    # OpenCanary
    ClassifierSignature(HoneypotPlatform.OPENCANARY, "opencanary-ssh", "ssh",
        re.compile(rb"SSH-2\.0-OpenSSH_5\.9p1 Debian-5ubuntu1\.1", re.I), 0.90,
        "OpenCanary SSH default."),
    ClassifierSignature(HoneypotPlatform.OPENCANARY, "opencanary-ftp", "ftp",
        re.compile(rb"220.*FileZilla Server version 0\.[9]", re.I), 0.85,
        "OpenCanary FTP module."),
    ClassifierSignature(HoneypotPlatform.OPENCANARY, "opencanary-x-header", "http",
        re.compile(rb"X-Canary:", re.I), 0.97,
        "OpenCanary X-Canary header."),
    # Thinkst
    ClassifierSignature(HoneypotPlatform.THINKST, "thinkst-token-url", "http",
        re.compile(rb"canarytokens\.com|canarytokens\.org", re.I), 0.99,
        "Thinkst Canary token domain."),
    ClassifierSignature(HoneypotPlatform.THINKST, "thinkst-ssh-key-comment", "ssh",
        re.compile(rb"canary@[a-z0-9\-]+\.(canary|thinkst)", re.I), 0.96,
        "Thinkst SSH host key comment."),
    # HoneyD
    ClassifierSignature(HoneypotPlatform.HONEYD, "honeyd-smtp", "smtp",
        re.compile(rb"220 [a-z0-9\-]+ ESMTP Sendmail 8\.11\.[0-9]", re.I), 0.85,
        "HoneyD SMTP old Sendmail."),
    ClassifierSignature(HoneypotPlatform.HONEYD, "honeyd-ftp", "ftp",
        re.compile(rb"220 [a-z0-9\-]+ FTP server \(Version wu-2\.", re.I), 0.87,
        "HoneyD FTP wu-ftpd."),
    # Dionaea
    ClassifierSignature(HoneypotPlatform.DIONAEA, "dionaea-ftp", "ftp",
        re.compile(rb"220 DiskStation FTP server ready\.", re.I), 0.88,
        "Dionaea Synology impersonation."),
    ClassifierSignature(HoneypotPlatform.DIONAEA, "dionaea-smb", "smb",
        re.compile(rb"\xff\x53\x4d\x42\x72\x00\x00\x00\x00\x88", re.DOTALL), 0.82,
        "Dionaea SMB negotiate bytes."),
    # T-Pot
    ClassifierSignature(HoneypotPlatform.TPOT, "tpot-kibana-header", "http",
        re.compile(rb"kbn-name:|kbn-version:", re.I), 0.88,
        "T-Pot exposes Kibana with kbn-* headers on port 5601."),
    ClassifierSignature(HoneypotPlatform.TPOT, "tpot-spiderfoot", "http",
        re.compile(rb"<title>SpiderFoot</title>", re.I), 0.82,
        "T-Pot bundles SpiderFoot sometimes exposed on network."),
    # Conpot
    ClassifierSignature(HoneypotPlatform.CONPOT, "conpot-scada-strings", "http",
        re.compile(rb"Siemens AG|SIMATIC S7|S7-200|S7-300", re.I), 0.80,
        "Conpot impersonates Siemens SCADA devices."),
    ClassifierSignature(HoneypotPlatform.CONPOT, "conpot-snmp", "snmp",
        re.compile(rb"Conpot SNMP", re.I), 0.85,
        "Conpot SNMP explicit identifier."),
    # Elasticpot
    ClassifierSignature(HoneypotPlatform.ELASTICPOT, "elasticpot-index-error", "http",
        re.compile(rb"index_not_found_exception", re.I), 0.82,
        "Elasticpot returns canned index_not_found errors."),
    ClassifierSignature(HoneypotPlatform.ELASTICPOT, "elasticpot-old-version", "http",
        re.compile(rb'"number"\s*:\s*"[12]\.[0-9]\.[0-9]', re.I), 0.75,
        "Elasticpot uses ES 1.x/2.x versions extinct in production."),
    ClassifierSignature(HoneypotPlatform.ELASTICPOT, "elasticpot-tagline", "http",
        re.compile(rb"You Know, for Search", re.I), 0.65,
        "Elasticsearch root tagline."),
    # Mailoney
    ClassifierSignature(HoneypotPlatform.MAILONEY, "mailoney-banner-explicit", "smtp",
        re.compile(rb"ESMTP Mailoney", re.I), 0.97,
        "Mailoney exposes itself in SMTP banner."),
    ClassifierSignature(HoneypotPlatform.MAILONEY, "mailoney-size-zero", "smtp",
        re.compile(rb"250.*SIZE 0\b", re.I|re.DOTALL), 0.70,
        "Mailoney SIZE 0 capability giveaway."),
    # Honeytrap
    ClassifierSignature(HoneypotPlatform.HONEYTRAP, "honeytrap-server-header", "http",
        re.compile(rb"Server: Honeytrap|X-Honeytrap-Session:", re.I), 0.96,
        "Honeytrap explicit server header."),
    ClassifierSignature(HoneypotPlatform.HONEYTRAP, "honeytrap-go-server", "http",
        re.compile(rb"Server: Go-http-client/[0-9]", re.I), 0.55,
        "Go HTTP server on non-Go services is suspicious."),
    # Shockpot
    ClassifierSignature(HoneypotPlatform.SHOCKPOT, "shockpot-old-stack", "http",
        re.compile(rb"Apache/2\.2\.[0-9]+ \(Ubuntu\)", re.I), 0.60,
        "Shockpot default Apache 2.2 stack extinct post-2018."),
    # Wordpot
    ClassifierSignature(HoneypotPlatform.WORDPOT, "wordpot-explicit", "http",
        re.compile(rb"[Ww]ordpot", re.I), 0.95,
        "Wordpot name leak in response."),
    ClassifierSignature(HoneypotPlatform.WORDPOT, "wordpot-wp-login", "http",
        re.compile(rb'wp-login\.php.*name=["\']log["\']', re.I|re.DOTALL), 0.80,
        "Wordpot fake WordPress login."),
    # ADBHoney
    ClassifierSignature(HoneypotPlatform.ADBHONEY, "adbhoney-cnxn", "adb",
        re.compile(rb"CNXN.{12}device::", re.DOTALL), 0.90,
        "ADBHoney fake Android CNXN packet."),
    # s0i37
    ClassifierSignature(HoneypotPlatform.S0I37_DEFENCE, "s0i37-short-response", "generic",
        re.compile(rb"^.{1,16}$", re.DOTALL), 0.45,
        "s0i37 short response. Low confidence alone."),
    # Glutton
    ClassifierSignature(HoneypotPlatform.GLUTTON, "glutton-null-banner", "generic",
        re.compile(rb"^\x00{4,16}$", re.DOTALL), 0.55,
        "Glutton null-byte banner."),
    # Generic
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
                143:"imap",443:"http",445:"smb",502:"modbus",3389:"rdp",
                5601:"http",8080:"http",8443:"http",9200:"http",20000:"dnp3"
                }.get(port, "generic")

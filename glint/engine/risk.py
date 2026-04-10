from dataclasses import dataclass, field
from glint.collectors.http_headers import HeaderAnalysis, analyze as analyze_headers
from glint.collectors.ip_reputation import IPReputation, collect as collect_ip
from glint.engine import dimensions
from glint.engine import entropy
from glint.engine.dimensions import Finding, DimensionScore


WEIGHTS = {
    "network":        0.35,
    "anonymity":      0.30,
    "data_exposure":  0.25,
    "ip_reputation":  0.10,
}


def _risk_level(score: float) -> str:
    if score >= 76:
        return "CRITICAL"
    if score >= 51:
        return "HIGH"
    if score >= 26:
        return "MEDIUM"
    return "LOW"


@dataclass
class ScanResult:
    scan_id: str
    composite_score: float
    risk_level: str
    identity_entropy_score: float
    dimensions: list[DimensionScore]
    findings: list[Finding]
    server_observed: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "scan_id":                  self.scan_id,
            "composite_score":          self.composite_score,
            "risk_level":               self.risk_level,
            "identity_entropy_score":   self.identity_entropy_score,
            "dimensions": [
                {
                    "name":     d.name,
                    "score":    d.score,
                    "findings": [_finding_to_dict(f) for f in d.findings],
                }
                for d in self.dimensions
            ],
            "findings": [_finding_to_dict(f) for f in self.findings],
            "server_observed": self.server_observed,
        }


def _finding_to_dict(f: Finding) -> dict:
    return {
        "id":          f.id,
        "finding_key": f.finding_key,
        "severity":    f.severity,
        "title":       f.title,
        "description": f.description,
        "dimension":   f.dimension,
        "evidence":    f.evidence,
    }


def run(scan_id: str, payload: dict, remote_ip: str, request) -> ScanResult:
    browser = payload.get("browser", {})

    headers    = analyze_headers(request, browser)
    ip_rep     = collect_ip(remote_ip)
    entropy_score = entropy.calculate(browser)

    dim_anonymity     = dimensions.score_anonymity(browser)
    dim_network       = dimensions.score_network(browser, headers, remote_ip, ip_rep)
    dim_data_exposure = dimensions.score_data_exposure(browser)
    dim_ip_reputation = dimensions.score_ip_reputation(ip_rep)

    all_dimensions = [dim_anonymity, dim_network, dim_data_exposure, dim_ip_reputation]

    composite = sum(
        d.score * WEIGHTS[d.name]
        for d in all_dimensions
    )
    composite = round(min(composite, 100.0), 2)

    all_findings = []
    for d in all_dimensions:
        all_findings.extend(d.findings)

    server_observed = {
        "remote_ip":    remote_ip,
        "user_agent":   request.headers.get("User-Agent", "unknown"),
        "ip_reputation": {
            "country":      ip_rep.country,
            "country_code": ip_rep.country_code,
            "isp":          ip_rep.isp,
            "is_proxy":     ip_rep.is_proxy,
            "is_hosting":   ip_rep.is_hosting,
            "timezone":     ip_rep.timezone,
            "available":    ip_rep.available,
        },
        "header_analysis": {
            "accept_language": headers.accept_language,
            "lang_mismatch":   headers.lang_mismatch,
            "lang_header":     headers.lang_header,
            "lang_navigator":  headers.lang_navigator,
        },
    }

    return ScanResult(
        scan_id=scan_id,
        composite_score=composite,
        risk_level=_risk_level(composite),
        identity_entropy_score=entropy_score,
        dimensions=all_dimensions,
        findings=all_findings,
        server_observed=server_observed,
    )
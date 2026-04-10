import dns.resolver
import httpx
from dataclasses import dataclass, field


@dataclass
class ResolverInfo:
    ip: str
    is_clean: bool
    isp: str | None = None
    country: str | None = None


@dataclass
class DNSLeakResult:
    resolvers: list[ResolverInfo]
    leaked: bool
    available: bool


def collect(clean_resolvers: list[str]) -> DNSLeakResult:
    try:
        resolver     = dns.resolver.Resolver()
        nameservers  = resolver.nameservers
        clean_set    = set(clean_resolvers)
        resolver_infos: list[ResolverInfo] = []
        leaked = False

        for ns_ip in nameservers:
            if ns_ip in clean_set:
                resolver_infos.append(ResolverInfo(ip=ns_ip, is_clean=True))
                continue

            leaked = True
            isp     = None
            country = None

            try:
                resp = httpx.get(
                    f"http://ip-api.com/json/{ns_ip}",
                    params={"fields": "status,isp,country"},
                    timeout=3.0,
                )
                data = resp.json()
                if data.get("status") == "success":
                    isp     = data.get("isp")
                    country = data.get("country")
            except Exception:
                pass

            resolver_infos.append(ResolverInfo(
                ip=ns_ip,
                is_clean=False,
                isp=isp,
                country=country,
            ))

        return DNSLeakResult(
            resolvers=resolver_infos,
            leaked=leaked,
            available=True,
        )

    except Exception:
        return DNSLeakResult(resolvers=[], leaked=False, available=False)

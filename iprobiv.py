import argparse
import sys

import requests
from rich.console import Console
from rich.table import Table

console = Console()


def parse_args():
    parser = argparse.ArgumentParser(
        description="IP OSINT lookup across multiple public APIs."
    )
    parser.add_argument(
        "--ip",
        required=True,
        help="Target IP address to look up.",
    )
    parser.add_argument(
        "--raw",
        action="store_true",
        help="Print raw JSON response from each source instead of formatted tables.",
    )
    return parser.parse_args()


def build_sources(ip: str) -> dict:
    return {
        "ipinfo.io": f"https://ipinfo.io/{ip}",
        "ipwho.is": f"https://ipwho.is/{ip}?security=1",
        "ip2location.io": f"https://api.ip2location.io/?ip={ip}",
        "ip-api.com": f"http://ip-api.com/json/{ip}?fields=66846719",
        "ipwhois.io": f"https://ipwhois.app/json/{ip}",
        "ipapi.co": f"https://ipapi.co/{ip}/json/",
        "api.db-ip.com": f"https://api.db-ip.com/v2/free/{ip}",
        "ipapi.is": f"https://api.ipapi.is?q={ip}",
        "ipwho.org": f"https://api.ipwho.org/ip/{ip}",
        "ipcity": f"https://ip.city/api/{ip}",
        "ipgeolocation.io": f"https://api.ipgeolocation.io/ipgeo?ip={ip}",
        "geoapify": f"https://api.geoapify.com/v1/ipinfo?ip={ip}",
        "iplocate.io": f"https://iplocate.io/api/lookup/{ip}",
        "ipbase.com": f"https://api.ipbase.com/v2/info?ip={ip}",
        "freeipapi.com": f"https://freeipapi.com/api/json/{ip}",
        "geojs.io": f"https://get.geojs.io/v1/ip/geo/{ip}.json",
        "api.ip.sb": f"https://api.ip.sb/geoip/{ip}",
        "internetdb.shodan.io": f"https://internetdb.shodan.io/{ip}",
    }


def flatten(obj, parent=""):
    result = {}
    if isinstance(obj, dict):
        for k, v in obj.items():
            key = f"{parent}.{k}" if parent else str(k)
            result.update(flatten(v, key))
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            key = f"{parent}.{i}" if parent else str(i)
            result.update(flatten(v, key))
    else:
        result[parent] = obj
    return result


def format_value(value):
    if value is None:
        return "None"
    return str(value)


def main():
    args = parse_args()
    ip = args.ip
    raw = args.raw

    sources = build_sources(ip)

    for name, url in sources.items():
        console.rule(f"[bold green]{name}[/bold green]")
        try:
            r = requests.get(url, timeout=10)
            r.raise_for_status()

            try:
                data = r.json()
            except ValueError:
                console.print(r.text)
                continue

            if raw:
                console.print_json(data=data)
                continue

            flat = flatten(data)
            table = Table(show_header=True, header_style="bold magenta")
            table.title = name
            table.add_column("Field", style="cyan")
            table.add_column("Value", style="yellow")

            for key in sorted(flat.keys()):
                table.add_row(key, format_value(flat[key]))

            console.print(table)
        except Exception as e:
            console.print(f"[red]Request error for {name}: {e}[/red]")

    sys.exit(0)


if __name__ == "__main__":
    main()
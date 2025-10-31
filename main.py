#!/usr/bin/env python3
import argparse
import sys
from pathlib import Path

from phishing_tool import analyze_url, analyze_email


def _print_report(title: str, data: dict):
    print("=" * 60)
    print(title)
    print("-" * 60)
    for k in ["input", "host", "registrable_domain", "tld", "sender", "sender_domain", "links"]:
        if k in data and data[k]:
            print(f"{k}: {data[k]}")
    print(f"Verdict: {data.get('verdict', 'Unknown')}")
    print("Reasons:")
    for r in data.get("reasons", []):
        print(f" - {r}")
    print("=" * 60)


def main():
    p = argparse.ArgumentParser(description="Phishing Awareness Tool - URL and Email Analyzer")
    p.add_argument("--mode", choices=["url", "email"], help="Type of input to analyze")
    p.add_argument("--input", help="URL string or email text (use --mode to specify)")
    p.add_argument("--input-file", help="Path to a file containing email text")

    args = p.parse_args()

    if not args.mode:
        print("Phishing Awareness Tool")
        print("Select mode: [1] URL  [2] Email")
        choice = input("Enter 1 or 2: ").strip()
        args.mode = "url" if choice == "1" else "email"

    if args.mode == "url":
        url = args.input
        if not url:
            url = input("Enter URL to analyze: ").strip()
        result = analyze_url(url)
        _print_report("URL Analysis", result)
        return 0

    if args.mode == "email":
        text = args.input
        if args.input_file:
            fp = Path(args.input_file)
            if not fp.exists():
                print(f"File not found: {fp}")
                return 2
            text = fp.read_text(encoding="utf-8", errors="ignore")
        if not text:
            print("Paste email text (end with Ctrl-D):\n")
            try:
                text = sys.stdin.read()
            except KeyboardInterrupt:
                return 130
        result = analyze_email(text)
        _print_report("Email Analysis", result)
        return 0

    return 1


if __name__ == "__main__":
    raise SystemExit(main())

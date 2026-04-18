#!/usr/bin/env python3
"""DeFi Security Toolkit CLI"""
import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent / "src"))

from defi_security_toolkit.flash_detector import FlashLoanDetector, TVLMonitor

def analyze_trace(trace_file: str):
    """Analyze transaction trace"""
    with open(trace_file) as f:
        trace = json.load(f)
    
    detector = FlashLoanDetector()
    result = detector.analyze_transaction_trace(trace)
    
    print("=" * 70)
    print("Flash Loan Attack Analysis")
    print("=" * 70)
    print(f"Detected: {result.detected}")
    print(f"Confidence: {result.confidence*100:.1f}%")
    print(f"Attack Type: {result.attack_type.value}")
    print(f"Severity: {result.severity}")
    print(f"\nExplanation: {result.explanation}")
    print(f"\nIndicators:")
    for ind in result.indicators:
        print(f"  • {ind}")
    print("=" * 70)

def check_contract(contract_file: str):
    """Check contract for vulnerable patterns"""
    with open(contract_file) as f:
        code = f.read()
    
    detector = FlashLoanDetector()
    issues = detector.check_contract_vulnerable_patterns(code)
    
    print("=" * 70)
    print("Contract Vulnerability Analysis")
    print("=" * 70)
    
    if issues:
        print(f"⚠️  Found {len(issues)} potential vulnerabilities:")
        for issue in issues:
            print(f"  • {issue}")
    else:
        print("✅ No obvious flash loan vulnerabilities detected")
    print("=" * 70)

def demo_tvl_monitor():
    """Demo TVL monitoring"""
    monitor = TVLMonitor()
    
    # Simulate protocol TVL
    protocols = {
        "Aave": {"baseline": 1000000000, "current": 950000000},
        "Uniswap": {"baseline": 500000000, "current": 200000000},  # 60% drop!
        "Compound": {"baseline": 300000000, "current": 290000000}
    }
    
    print("=" * 70)
    print("TVL Monitoring Dashboard")
    print("=" * 70)
    
    for protocol, data in protocols.items():
        monitor.set_baseline(protocol, data["baseline"])
        result = monitor.detect_anomaly(protocol, data["current"])
        
        emoji = {
            "critical": "🚨",
            "warning": "⚠️",
            "normal": "✅",
            "unknown": "❓"
        }.get(result["status"], "❓")
        
        print(f"\n{emoji} {protocol}")
        print(f"   Status: {result['status'].upper()}")
        print(f"   Change: {result['change_percent']:+.1f}%")
        print(f"   {result['message']}")
    
    print("=" * 70)

def main():
    parser = argparse.ArgumentParser(description="DeFi Security Toolkit")
    subparsers = parser.add_subparsers(dest="command", help="Available commands")
    
    # Flash loan analyzer
    flash_parser = subparsers.add_parser("flash-analyze", help="Analyze transaction for flash loan")
    flash_parser.add_argument("trace", help="JSON file with transaction trace")
    
    # Contract checker
    contract_parser = subparsers.add_parser("check-contract", help="Check contract for vulnerabilities")
    contract_parser.add_argument("file", help="Solidity contract file")
    
    # TVL monitor
    subparsers.add_parser("tvl-monitor", help="Monitor TVL changes")
    
    args = parser.parse_args()
    
    if args.command == "flash-analyze":
        analyze_trace(args.trace)
    elif args.command == "check-contract":
        check_contract(args.file)
    elif args.command == "tvl-monitor":
        demo_tvl_monitor()
    else:
        # Run all demos
        print("DeFi Security Toolkit - Running demos...\n")
        demo_tvl_monitor()
        
        print("\nFlash Loan Detection Demo:")
        sample_trace = [
            {"to": "0x123", "input": "flashLoan(1000000,0xabc)"},
            {"to": "0x456", "input": "swap(1000,0)"},
            {"to": "0x789", "input": "transfer(profit)"}
        ]
        detector = FlashLoanDetector()
        result = detector.analyze_transaction_trace(sample_trace)
        print(f"Detected: {result.detected}, Confidence: {result.confidence*100:.1f}%")
        print(f"Attack Type: {result.attack_type.value}")

if __name__ == "__main__":
    main()

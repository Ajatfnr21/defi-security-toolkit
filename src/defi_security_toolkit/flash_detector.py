"""
DeFi Security Toolkit - Flash Loan Attack Detector
"""
import re
from typing import List, Dict, Optional, Tuple
from dataclasses import dataclass
from enum import Enum

class AttackType(Enum):
    FLASH_LOAN = "flash_loan"
    PRICE_MANIPULATION = "price_manipulation"
    REENTRANCY = "reentrancy"
    ORACLE_MANIPULATION = "oracle_manipulation"
    UNKNOWN = "unknown"

@dataclass
class FlashLoanDetection:
    detected: bool
    confidence: float
    attack_type: AttackType
    indicators: List[str]
    explanation: str
    severity: str

class FlashLoanDetector:
    """Detects flash loan attack patterns in transaction traces"""
    
    FLASH_LOAN_SIGNATURES = [
        "flashLoan", "flashloan", "flash_loan",
        "0xab9c4b5d",  # Aave flashLoan
        "0x6b07c94f",  # dYdX operate
        "0x2e9c55b4",  # Uniswap V3 flash
    ]
    
    PRICE_MANIPULATION_PATTERNS = [
        "swap", "getReserves", "getAmountsOut",
        "balanceOf", "_reserve0", "_reserve1"
    ]
    
    def __init__(self):
        self.known_attack_txs = self._load_known_attacks()
    
    def _load_known_attacks(self) -> Dict[str, str]:
        """Load known flash loan attack transaction hashes"""
        return {
            "0x35f5...": "Cream Finance Flash Loan",
            "0x8967...": "Yearn Finance Exploit",
            "0x46b8...": "Cream v1 Exploit",
        }
    
    def analyze_transaction_trace(self, trace: List[Dict]) -> FlashLoanDetection:
        """
        Analyze transaction trace for flash loan patterns
        
        Args:
            trace: List of call frames from transaction trace
        
        Returns:
            FlashLoanDetection with analysis results
        """
        indicators = []
        
        # Step 1: Check for flash loan pattern
        has_flash_loan = False
        flash_loan_index = -1
        
        for i, call in enumerate(trace):
            call_data = call.get("input", "")
            
            if any(sig in call_data for sig in self.FLASH_LOAN_SIGNATURES):
                has_flash_loan = True
                flash_loan_index = i
                indicators.append(f"Flash loan detected at call index {i}")
                break
        
        if not has_flash_loan:
            return FlashLoanDetection(
                detected=False,
                confidence=0.0,
                attack_type=AttackType.UNKNOWN,
                indicators=[],
                explanation="No flash loan pattern detected",
                severity="none"
            )
        
        # Step 2: Check for price manipulation after flash loan
        has_price_manipulation = False
        
        for i in range(flash_loan_index + 1, min(flash_loan_index + 10, len(trace))):
            call = trace[i]
            call_data = call.get("input", "").lower()
            
            if any(pattern in call_data for pattern in self.PRICE_MANIPULATION_PATTERNS):
                has_price_manipulation = True
                indicators.append(f"Price manipulation pattern at index {i}: {call.get('to', 'unknown')}")
        
        # Step 3: Check for profit extraction
        has_profit = False
        for call in trace:
            if any(keyword in str(call).lower() for keyword in ["transfer", "withdraw", "swap"]):
                if call.get("value", 0) > 0 or "profit" in str(call).lower():
                    has_profit = True
                    indicators.append("Potential profit extraction detected")
                    break
        
        # Determine attack type
        if has_price_manipulation and has_profit:
            attack_type = AttackType.FLASH_LOAN
            confidence = 0.85
            severity = "critical"
            explanation = "Flash loan attack with price manipulation likely. Pattern: Borrow -> Manipulate -> Profit -> Repay"
        elif has_price_manipulation:
            attack_type = AttackType.PRICE_MANIPULATION
            confidence = 0.70
            severity = "high"
            explanation = "Price manipulation detected after flash loan. Possible attack attempt."
        else:
            attack_type = AttackType.FLASH_LOAN
            confidence = 0.60
            severity = "medium"
            explanation = "Flash loan detected but unclear if malicious. May be legitimate arbitrage."
        
        return FlashLoanDetection(
            detected=True,
            confidence=confidence,
            attack_type=attack_type,
            indicators=indicators,
            explanation=explanation,
            severity=severity
        )
    
    def check_contract_vulnerable_patterns(self, code: str) -> List[str]:
        """Check if contract code has flash loan vulnerable patterns"""
        vulnerabilities = []
        
        # Pattern 1: Price oracle manipulation vulnerability
        if re.search(r'getAmountsOut|getReserves|balanceOf.*price', code, re.IGNORECASE):
            if not re.search(r'oracle.*time.*weighted|TWAP', code, re.IGNORECASE):
                vulnerabilities.append("Price oracle vulnerable to manipulation (no TWAP protection)")
        
        # Pattern 2: No reentrancy guard on price-sensitive functions
        if re.search(r'function.*swap|function.*exchange', code, re.IGNORECASE):
            if not re.search(r'nonReentrant|lock', code, re.IGNORECASE):
                vulnerabilities.append("Swap/exchange functions without reentrancy protection")
        
        # Pattern 3: Critical operations with external calls
        if re.search(r'call.*value|delegatecall', code, re.IGNORECASE):
            vulnerabilities.append("External calls detected - verify reentrancy protection")
        
        return vulnerabilities

class TVLMonitor:
    """Monitor Total Value Locked changes"""
    
    def __init__(self):
        self.baselines = {}
    
    def set_baseline(self, protocol: str, tvl: float):
        """Set baseline TVL for protocol"""
        self.baselines[protocol] = tvl
    
    def detect_anomaly(self, protocol: str, current_tvl: float) -> Dict:
        """Detect TVL anomalies"""
        if protocol not in self.baselines:
            return {"status": "unknown", "change_percent": 0}
        
        baseline = self.baselines[protocol]
        change = (current_tvl - baseline) / baseline * 100
        
        if change < -50:
            return {
                "status": "critical",
                "change_percent": change,
                "message": f"TVL dropped {abs(change):.1f}% - Possible exploit!"
            }
        elif change < -20:
            return {
                "status": "warning",
                "change_percent": change,
                "message": f"TVL dropped {abs(change):.1f}% - Investigate"
            }
        else:
            return {
                "status": "normal",
                "change_percent": change,
                "message": "TVL within normal range"
            }

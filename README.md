# DeFi Security Toolkit 🛡️

[![Python](https://img.shields.io/badge/Python-3.11%2B-blue)]()
[![License](https://img.shields.io/badge/License-MIT-green.svg)]()

**Comprehensive security toolkit for DeFi protocol auditing and risk assessment.**

## ✨ Features

- 🔦 **Flash Loan Detector** - Identify flash loan attack vectors
- 📊 **TVL Tracker** - Real-time total value locked monitoring
- 💰 **IL Calculator** - Impermanent loss estimation tools
- 🎯 **Exploit Simulators** - Test attack hypotheses safely
- 📈 **Risk Dashboard** - Visual risk metrics and scoring
- 🔗 **Protocol Scanner** - Automated security checks

## 🚀 Quick Start

```bash
pip install defi-security-toolkit
python -m defi_toolkit scan --protocol aave
```

## 🛠️ Tools Included

| Tool | Purpose | Command |
|------|---------|---------|
| `flash_scan` | Flash loan detection | `flash_scan contract.sol` |
| `tvl_monitor` | TVL tracking | `tvl_monitor --protocol compound` |
| `il_calc` | Impermanent loss | `il_calc --pool 0x...` |
| `exploit_sim` | Attack simulation | `exploit_sim --target 0x...` |
| `risk_score` | Risk assessment | `risk_score --protocol uniswap` |

## 📊 Supported Protocols

- Aave V2/V3
- Compound V2/V3
- Uniswap V2/V3
- Curve Finance
- Convex Finance
- Yearn Finance
- And more...

## 🎯 Use Cases

- **Protocol Developers** - Pre-launch security checks
- **Security Researchers** - Vulnerability discovery
- **DeFi Investors** - Risk assessment before investing
- **Auditors** - Automated first-pass analysis

## 📄 License

MIT License - see [LICENSE](LICENSE)

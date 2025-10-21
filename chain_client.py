import os
from typing import Dict, Any, Optional
from web3 import Web3, HTTPProvider
from web3.exceptions import ContractLogicError
from common import chain_from_hint
import datetime as _dt

# Настройки Infura (или другой провайдер)
INFURA_URL = os.getenv("INFURA_URL", "https://mainnet.infura.io/v3/YOUR_INFURA_KEY")  # Замени на свой ключ
w3 = Web3(HTTPProvider(INFURA_URL))

# ABI для проверок токена
ERC20_ABI = [
    {"constant": True, "inputs": [], "name": "totalSupply", "outputs": [{"name": "", "type": "uint256"}], "type": "function"},
    {"constant": True, "inputs": [{"name": "_owner", "type": "address"}], "name": "balanceOf", "outputs": [{"name": "balance", "type": "uint256"}], "type": "function"},
    {"constant": False, "inputs": [{"name": "_to", "type": "address"}, {"name": "_value", "type": "uint256"}], "name": "transfer", "outputs": [{"name": "success", "type": "bool"}], "type": "function"},
]
TAX_ABI = [
    {"constant": True, "inputs": [], "name": "taxFee", "outputs": [{"name": "", "type": "uint256"}], "type": "function"},
]
OWNER_ABI = [
    {"constant": True, "inputs": [], "name": "owner", "outputs": [{"name": "", "type": "address"}], "type": "function"},
]
PAUSABLE_ABI = [
    {"constant": True, "inputs": [], "name": "paused", "outputs": [{"name": "", "type": "bool"}], "type": "function"},
]
UPGRADEABLE_ABI = [
    {"constant": True, "inputs": [], "name": "implementation", "outputs": [{"name": "", "type": "address"}], "type": "function"},
]
MINT_ABI = [
    {"constant": False, "inputs": [{"name": "_to", "type": "address"}, {"name": "_amount", "type": "uint256"}], "name": "mint", "outputs": [{"name": "", "type": "bool"}], "type": "function"},
]
MAX_TX_ABI = [
    {"constant": True, "inputs": [], "name": "maxTxAmount", "outputs": [{"name": "", "type": "uint256"}], "type": "function"},
]
MAX_WALLET_ABI = [
    {"constant": True, "inputs": [], "name": "maxWalletAmount", "outputs": [{"name": "", "type": "uint256"}], "type": "function"},
]
UNICRYPT_ABI = [
    {"inputs": [], "name": "getLockedTokens", "outputs": [{"internalType": "uint256", "name": "", "type": "uint256"}], "stateMutability": "view", "type": "function"},
    {"inputs": [], "name": "unlockTime", "outputs": [{"internalType": "uint256", "name": "", "type": "uint256"}], "stateMutability": "view", "type": "function"},
]

def fetch_onchain_factors(address: Optional[str], chain_hint: str = "ethereum") -> Dict[str, Any]:
    """
    Returns a factors dict for risk engine.
    Keys: honeypot, blacklist, pausable, upgradeable, mint, maxTx, maxWallet, taxes{buy,sell}, owner, lp_lock
    """
    if not address or not w3.is_connected():
        return {
            "honeypot": False,
            "blacklist": False,
            "pausable": False,
            "upgradeable": False,
            "mint": False,
            "maxTx": None,
            "maxWallet": None,
            "taxes": {"buy": 0.0, "sell": 0.0},
            "owner": None,
            "lp_lock": {"status": "unknown", "amount": 0, "until": None},
        }

    contract = w3.eth.contract(address=address, abi=ERC20_ABI + TAX_ABI + OWNER_ABI + PAUSABLE_ABI + UPGRADEABLE_ABI + MINT_ABI + MAX_TX_ABI + MAX_WALLET_ABI)
    factors = {}

    # Honeypot: Симуляция buy/sell
    try:
        dummy_tx = contract.functions.transfer(w3.eth.default_account or "0x0000000000000000000000000000000000000001", 1).build_transaction({'from': '0x0000000000000000000000000000000000000000', 'gas': 100000, 'gasPrice': w3.to_wei('20', 'gwei')})
        w3.eth.call(dummy_tx)
        factors["honeypot"] = False
    except ContractLogicError:
        factors["honeypot"] = True

    # Blacklist: Нет прямой проверки, дефолт False
    factors["blacklist"] = False

    # Pausable
    try:
        factors["pausable"] = contract.functions.paused().call()
    except Exception:
        factors["pausable"] = False

    # Upgradeable
    try:
        factors["upgradeable"] = bool(contract.functions.implementation().call())
    except Exception:
        factors["upgradeable"] = False

    # Mint
    try:
        contract.functions.mint(w3.eth.default_account or "0x0000000000000000000000000000000000000001", 1).call()
        factors["mint"] = True
    except ContractLogicError:
        factors["mint"] = False

    # MaxTx/MaxWallet
    try:
        factors["maxTx"] = contract.functions.maxTxAmount().call()
    except Exception:
        factors["maxTx"] = None
    try:
        factors["maxWallet"] = contract.functions.maxWalletAmount().call()
    except Exception:
        factors["maxWallet"] = None

    # Taxes
    try:
        tax = contract.functions.taxFee().call() / 100
        factors["taxes"] = {"buy": tax, "sell": tax}
    except Exception:
        factors["taxes"] = {"buy": 0.0, "sell": 0.0}

    # Owner
    try:
        owner = contract.functions.owner().call()
        factors["owner"] = owner if owner != '0x0000000000000000000000000000000000000000' else None
    except Exception:
        factors["owner"] = None

    # LP Lock (Unicrypt V2)
    unicrypt_address = "0x663A5C229c09b049E36dCeF2a9DD9bA53590eB2b"
    try:
        unicrypt_contract = w3.eth.contract(address=unicrypt_address, abi=UNICRYPT_ABI)
        locked_amount = unicrypt_contract.functions.getLockedTokens().call()
        unlock_time = unicrypt_contract.functions.unlockTime().call()
        factors["lp_lock"] = {
            "status": "locked" if locked_amount > 0 else "unlocked",
            "amount": locked_amount,
            "until": _dt.utcfromtimestamp(unlock_time).strftime("%Y-%m-%d") if unlock_time else None
        }
    except Exception:
        factors["lp_lock"] = {"status": "unknown", "amount": 0, "until": None}

    return factors

def check_lp_lock_v2(chain: str, lp_addr: Optional[str]) -> Dict[str, Any]:
    """
    Check LP lock status for given LP address.
    """
    if not lp_addr or chain != "ethereum":
        return {"provider": "unicrypt", "lpAddress": lp_addr or "—", "until": "—", "status": "unknown", "amount": 0}
    
    try:
        unicrypt_contract = w3.eth.contract(address="0x663A5C229c09b049E36dCeF2a9DD9bA53590eB2b", abi=UNICRYPT_ABI)
        locked_amount = unicrypt_contract.functions.getLockedTokens().call()
        unlock_time = unicrypt_contract.functions.unlockTime().call()
        return {
            "provider": "unicrypt",
            "lpAddress": lp_addr,
            "status": "locked" if locked_amount > 0 else "unlocked",
            "amount": locked_amount,
            "until": _dt.utcfromtimestamp(unlock_time).strftime("%Y-%m-%d") if unlock_time else "—"
        }
    except Exception:
        return {"provider": "unicrypt", "lpAddress": lp_addr or "—", "until": "—", "status": "unknown", "amount": 0}

from brownie import accounts, LamportTest2
from brownie.network import gas_price
from brownie.network.gas.strategies import LinearScalingStrategy

gas_strategy = LinearScalingStrategy("60 gwei", "70 gwei", 1.1)

# if network.show_active() == "development":
gas_price(gas_strategy)

def main():
    # Replace `ContractName` with the actual name of your contract
    contract = LamportTest2.deploy({'from': accounts[0]})
    print(f"Contract deployed: {contract.address}")

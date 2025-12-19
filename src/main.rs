//! Example showing how to send an [EIP-7702](https://github.com/ethereum/EIPs/blob/master/EIPS/eip-7702.md) transaction.

use alloy::{
    eips::eip7702::Authorization,
    network::{TransactionBuilder, TransactionBuilder7702},
    primitives::U256,
    providers::{Provider, ProviderBuilder},
    rpc::types::TransactionRequest,
    signers::{local::PrivateKeySigner, SignerSync},
    sol,
};
use eyre::Result;
use std::str::FromStr;

// Load contract from compiled JSON artifact
// Extract bytecode from: out/delegate.sol/Delegate.json
sol!(
    #[allow(missing_docs)]
    #[sol(rpc, bytecode = "0x6080604052348015600e575f5ffd5b5061018d8061001c5f395ff3fe608060405234801561000f575f5ffd5b506004361061004a575f3560e01c80630a493f921461004e5780637b3ab2d0146100585780639ee1a44014610062578063d49ba5801461006c575b5f5ffd5b610056610076565b005b6100606100e9565b005b61006a610117565b005b610074610145565b005b3073ffffffffffffffffffffffffffffffffffffffff163273ffffffffffffffffffffffffffffffffffffffff163373ffffffffffffffffffffffffffffffffffffffff167f661edff2d7bf0ce6f6d6b30e60d85af6733d37cfeec1d345c001591c6023192d60405160405180910390a4565b7fbcdfe0d5b27dd186282e187525415c57ea3077c34efb39148111e4d342e7ab0e60405160405180910390a1565b7f2d67bb91f17bca05af6764ab411e86f4ddf757adb89fcec59a7d21c525d4171260405160405180910390a1565b61014d6100e9565b610155610117565b56fea2646970667358221220a50aeca7b8cd16e57014596dd9e84d040b63f0351ca5fc97e639c5a0b324d82664736f6c634300081e0033")]
    contract Delegate {
        event Hello();
        event World();
        event Address(address indexed sender_address, address indexed origin_address, address indexed this_address);

        function emitHello() public {
            emit Hello();
        }
        function emitWorld() public {
            emit World();
        }
        function emitHelloWorld() public {
            emitHello();
            emitWorld();
        }
        function emitAddress() public {
            emit Address(msg.sender, tx.origin, address(this));
        }
    }
);

#[tokio::main]
async fn main() -> Result<()> {
    // Connect to localhost node (default: http://localhost:8545)
    let rpc_url = reqwest::Url::parse("https://sepolia.infura.io/v3/97d0b8363e1f4e8098afaaa438753e9a")?;
    
    // Create two users, Alice and Bob.
    // Alice will sign the authorization and Bob will send the transaction.
    // Using common test private keys (replace with your own if needed)
    let alice_key = "933d34fc71cf5b30907b4904c71cfc40d485d8e66b7a1a1936e1185578f3558f"; // Anvil default key 0
    let bob_key = "5eee9528d33beed8fb1cb175c212d32f1ccac11aa9df0bb9a45025b49a8edcc3"; // Anvil default key 1
    
    let alice: PrivateKeySigner = PrivateKeySigner::from_str(alice_key)?;
    let bob: PrivateKeySigner = PrivateKeySigner::from_str(bob_key)?;

    // Create a provider with the wallet for only Bob (not Alice).
    let provider = ProviderBuilder::new().wallet(bob.clone()).connect_http(rpc_url);

    // // Deploy the contract Alice will authorize.
    // let contract = Delegate::deploy(&provider).await?;

    // 方式2: 直接使用地址字符串
    let contract_address = Address::from_str("0x6ee338fe36c497aaa76b3a75a24c05f498b37030")?;

    // 创建已部署的合约实例
    let contract = Delegate::new(contract_address, &provider);

    // Get chain ID from the provider
    let chain_id = provider.get_chain_id().await?;
    
    // Create an authorization object for Alice to sign.
    let authorization = Authorization {
        chain_id: U256::from(chain_id),
        // Reference to the contract that will be set as code for the authority.
        address: *contract.address(),
        nonce: provider.get_transaction_count(alice.address()).await?,
    };

    // Alice signs the authorization.
    let signature = alice.sign_hash_sync(&authorization.signature_hash())?;
    let signed_authorization = authorization.into_signed(signature);

    // Collect the calldata required for the transaction.
    let call = contract.emitAddress();
    let emit_address_calldata = call.calldata().to_owned();

    // Build the transaction.
    let tx = TransactionRequest::default()
        .with_to(alice.address())
        .with_authorization_list(vec![signed_authorization.clone()])
        .with_input(emit_address_calldata);

    // Send the transaction and wait for the broadcast.
    let pending_tx = provider.send_transaction(tx).await?;

    println!("Pending transaction... {}", pending_tx.tx_hash());

    // Wait for the transaction to be included and get the receipt.
    let receipt = pending_tx.get_receipt().await?;

    println!(
        "Transaction included in block {}",
        receipt.block_number.expect("Failed to get block number")
    );

    assert!(receipt.status());
    assert_eq!(receipt.from, bob.address());
    assert_eq!(receipt.to, Some(alice.address()));
    assert_eq!(receipt.inner.logs().len(), 1);
    assert_eq!(receipt.inner.logs()[0].address(), alice.address());

    // 解析 emit Address(msg.sender, tx.origin, address(this))事件
    // 事件: event Address(address indexed sender_address, address indexed origin_address, address indexed this_address);
    
    use alloy::primitives::{Address, keccak256};
    
    // 获取并解析事件日志
    let logs = receipt.inner.logs();
    // 假设只有一个 event（assert 已检查长度为 1）
    let log = &logs[0];

    // Address 事件的 topic: keccak256("Address(address,address,address)")
    let event_signature = b"Address(address,address,address)";
    let event_topic = keccak256(event_signature);

    // 确认 topic0 匹配该事件
    assert_eq!(log.topics()[0], event_topic, "Event topic mismatch");

    // 从 topics 解析3个indexed参数（都为Address类型，20字节，前补0到32字节）
    // topics[0] 是事件签名，topics[1-3] 是 indexed 参数
    let topics = log.topics();
    let sender_address = Address::from_slice(&topics[1].as_slice()[12..32]);
    let origin_address = Address::from_slice(&topics[2].as_slice()[12..32]);
    let this_address = Address::from_slice(&topics[3].as_slice()[12..32]);

    println!("解析Address事件:");
    println!("  msg.sender = {}", sender_address);
    println!("  tx.origin = {}", origin_address);
    println!("  address(this) = {}", this_address);

    // 断言：
    // - msg.sender = Bob（Bob 是外部调用者）
    // - tx.origin = Bob（Bob 是交易发起者）
    // - address(this) = Alice（代码在 Alice 地址执行）
    assert_eq!(sender_address, bob.address(), "msg.sender should be Bob");
    assert_eq!(origin_address, bob.address(), "tx.origin should be Bob");
    assert_eq!(this_address, alice.address(), "address(this) should be Alice");

    // 调用 emitHelloWorld()
    let call = contract.emitHelloWorld();
    let emit_hello_world_calldata = call.calldata().to_owned();
    let tx = TransactionRequest::default()
        .with_to(alice.address())
        .with_authorization_list(vec![signed_authorization])
        .with_input(emit_hello_world_calldata);
    let pending_tx = provider.send_transaction(tx).await?;
    let receipt = pending_tx.get_receipt().await?;

    assert!(receipt.status());
    assert_eq!(receipt.from, bob.address());
    assert_eq!(receipt.to, Some(alice.address()));
    assert_eq!(receipt.inner.logs().len(), 2);
    assert_eq!(receipt.inner.logs()[0].address(), alice.address());
    assert_eq!(receipt.inner.logs()[1].address(), alice.address());

    println!("批量执行事件完成，交易包含在区块 {}", receipt.block_number.expect("Failed to get block number"));

    Ok(())
}
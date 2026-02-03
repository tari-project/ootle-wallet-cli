use tari_template_lib_types::{Amount, ResourceAddress, ResourceType, VaultId};

#[derive(Debug, Clone)]
pub struct BalanceEntry {
    pub vault_address: Option<VaultId>,
    pub resource_address: ResourceAddress,
    pub balance: Amount,
    pub resource_type: ResourceType,
    pub num_outputs: usize,
    pub confidential_balance: Amount,
    pub token_symbol: Option<String>,
    pub divisibility: u8,
}

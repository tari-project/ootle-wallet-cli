use tari_engine_types::template_lib_models::{ResourceAddress, VaultId};
use tari_template_lib_types::{Amount, ResourceType};

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

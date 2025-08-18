//! Implement BSC upgrade message which is required during handshake with other BSC clients, e.g.,
//! geth.
use alloy_rlp::{Decodable, Encodable};
use bytes::{BufMut, Bytes, BytesMut};

/// The message id for the upgrade status message, used in the BSC handshake.
const UPGRADE_STATUS_MESSAGE_ID: u8 = 0x0b;

/// UpdateStatus packet introduced in BSC to notify peers whether to broadcast transaction or not.
/// It is used during the p2p handshake.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct UpgradeStatus {
    /// Extension for support customized features for BSC.
    pub extension: UpgradeStatusExtension,
}

impl Encodable for UpgradeStatus {
    fn encode(&self, out: &mut dyn BufMut) {
        UPGRADE_STATUS_MESSAGE_ID.encode(out);
        self.extension.encode(out);
    }
}

impl Decodable for UpgradeStatus {
    fn decode(buf: &mut &[u8]) -> alloy_rlp::Result<Self> {
        let message_id = u8::decode(buf)?;
        if message_id != UPGRADE_STATUS_MESSAGE_ID {
            return Err(alloy_rlp::Error::Custom("Invalid message ID"));
        }
        
        // BSC sends: 0x0b (message id) followed by [[disable_peer_tx_broadcast]]
        // The remaining bytes should be the extension wrapped in an extra list
        let extension = UpgradeStatusExtension::decode(buf)?;
        Ok(Self { extension })
    }
}

impl UpgradeStatus {
    /// Encode the upgrade status message into RLPx bytes.
    pub fn into_rlpx(self) -> Bytes {
        let mut out = BytesMut::new();
        self.encode(&mut out);
        out.freeze()
    }
}

/// The extension to define whether to enable or disable the flag.
/// This flag currently is ignored, and will be supported later.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct UpgradeStatusExtension {
    // TODO: support disable_peer_tx_broadcast flag
    /// To notify a peer to disable the broadcast of transactions or not.
    pub disable_peer_tx_broadcast: bool,
}

impl Encodable for UpgradeStatusExtension {
    fn encode(&self, out: &mut dyn BufMut) {
        // Encode as a list containing the boolean
        vec![self.disable_peer_tx_broadcast].encode(out);
    }
}

impl Decodable for UpgradeStatusExtension {
    fn decode(buf: &mut &[u8]) -> alloy_rlp::Result<Self> {
        // First try `[bool]` format
        if let Ok(values) = <Vec<bool>>::decode(buf) {
            if values.len() == 1 {
                return Ok(Self { disable_peer_tx_broadcast: values[0] });
            }
        }
        // Fallback to `[[bool]]` as sometimes seen on BSC
        let nested: Vec<Vec<bool>> = Decodable::decode(buf)?;
        if nested.len() == 1 && nested[0].len() == 1 {
            return Ok(Self { disable_peer_tx_broadcast: nested[0][0] });
        }
        Err(alloy_rlp::Error::Custom("Invalid extension format"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::hex;
    
    #[test]
    fn test_decode_bsc_upgrade_status() {
        // Raw wire message captured from a BSC peer.
        let raw = hex::decode("0bc180").unwrap();

        let mut slice = raw.as_slice();
        let decoded = UpgradeStatus::decode(&mut slice).expect("should decode");

        assert_eq!(decoded.extension.disable_peer_tx_broadcast, false);
        // the slice should be fully consumed
        assert!(slice.is_empty(), "all bytes must be consumed by decoder");
    }
}

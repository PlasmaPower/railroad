use Block;
use BlockInner;
use Signature;

extern crate hex;

use serde::Deserialize;

use serde_json::Value;

fn deser_block(json: Value) -> Block {
    Block::deserialize(json).expect("Failed to deserialize block")
}

#[test]
fn deser_send() {
    let block = deser_block(json!({
        "type": "send",
        "previous": "314BA8D9057678C1F53371C2DB3026C1FAC01EC8E7802FD9A2E8130FC523429E",
        "destination": "xrb_18gmu6engqhgtjnppqam181o5nfhj4sdtgyhy36dan3jr9spt84rzwmktafc",
        "balance": "0000007E37BE2022C0914B2680000000",
        "work": "478563b2d9facfd4",
        "signature": "F19CA177EFA8692C8CBF7478CE3213F56E4A85DF760DA7A9E69141849831F8FD79BA9ED89CEC807B690FB4AA42D5008F9DBA7115E63C935401F1F0EFA547BC00"
    }));
    assert_eq!(block.header.work, 0x478563b2d9facfd4);
    assert_eq!(block.header.signature, Signature::from_bytes(&hex::decode("F19CA177EFA8692C8CBF7478CE3213F56E4A85DF760DA7A9E69141849831F8FD79BA9ED89CEC807B690FB4AA42D5008F9DBA7115E63C935401F1F0EFA547BC00").unwrap()).unwrap());
    if let BlockInner::Send { previous, destination, balance } = block.inner {
        assert_eq!(&previous.0, hex::decode("314BA8D9057678C1F53371C2DB3026C1FAC01EC8E7802FD9A2E8130FC523429E").unwrap().as_slice());
        assert_eq!(destination, "xrb_18gmu6engqhgtjnppqam181o5nfhj4sdtgyhy36dan3jr9spt84rzwmktafc".parse().unwrap());
        assert_eq!(balance, 0x0000007E37BE2022C0914B2680000000);
    } else {
        panic!("Block deserialized to wrong type");
    }
}

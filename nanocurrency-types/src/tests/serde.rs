use Account;
use Block;
use BlockInner;
use BlockType;
use Network;

use hex;
use serde_json;

#[test]
fn send_block() {
    let json = r#"{
        "type": "send",
        "previous": "314BA8D9057678C1F53371C2DB3026C1FAC01EC8E7802FD9A2E8130FC523429E",
        "destination": "nano_18gmu6engqhgtjnppqam181o5nfhj4sdtgyhy36dan3jr9spt84rzwmktafc",
        "balance": "0000007E37BE2022C0914B2680000000",
        "work": "478563b2d9facfd4",
        "signature": "F19CA177EFA8692C8CBF7478CE3213F56E4A85DF760DA7A9E69141849831F8FD79BA9ED89CEC807B690FB4AA42D5008F9DBA7115E63C935401F1F0EFA547BC00"
    }
    "#;
    let block: Block = serde_json::from_str(json).expect("Failed to deserialize block");
    assert_eq!(block.ty(), BlockType::Send);
    assert_eq!(block.header.work, 0x478563b2d9facfd4);
    assert!(block.work_valid(Network::Live));
    assert_eq!(hex::encode_upper(&block.header.signature.to_bytes() as &[u8]), "F19CA177EFA8692C8CBF7478CE3213F56E4A85DF760DA7A9E69141849831F8FD79BA9ED89CEC807B690FB4AA42D5008F9DBA7115E63C935401F1F0EFA547BC00");
    if let BlockInner::Send {
        ref previous,
        ref balance,
        ref destination,
    } = block.inner
    {
        assert_eq!(
            previous.to_string(),
            "314BA8D9057678C1F53371C2DB3026C1FAC01EC8E7802FD9A2E8130FC523429E"
        );
        assert_eq!(*balance, 0x0000007E37BE2022C0914B2680000000);
        assert_eq!(
            destination.to_string(),
            "nano_18gmu6engqhgtjnppqam181o5nfhj4sdtgyhy36dan3jr9spt84rzwmktafc"
        );
    } else {
        panic!("block.inner was not a send");
    }
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(json).unwrap(),
        serde_json::to_value(block).expect("Failed to serialize block")
    );
}

#[test]
fn receive_block() {
    let json = r#"{
        "type": "receive",
        "previous": "F47B23107E5F34B2CE06F562B5C435DF72A533251CB414C51B2B62A8F63A00E4",
        "source": "19D3D919475DEED4696B5D13018151D1AF88B2BD3BCFF048B45031C1F36D1858",
        "work": "6acb5dd43a38d76a",
        "signature": "A13FD22527771667D5DFF33D69787D734836A3561D8A490C1F4917A05D77EA09860461D5FBFC99246A4EAB5627F119AD477598E22EE021C4711FACF4F3C80D0E"
    }
    "#;
    let block: Block = serde_json::from_str(json).expect("Failed to deserialize block");
    assert_eq!(block.ty(), BlockType::Receive);
    assert_eq!(block.header.work, 0x6acb5dd43a38d76a);
    assert!(block.work_valid(Network::Live));
    assert_eq!(hex::encode_upper(&block.header.signature.to_bytes() as &[u8]), "A13FD22527771667D5DFF33D69787D734836A3561D8A490C1F4917A05D77EA09860461D5FBFC99246A4EAB5627F119AD477598E22EE021C4711FACF4F3C80D0E");
    if let BlockInner::Receive {
        ref previous,
        ref source,
    } = block.inner
    {
        assert_eq!(
            previous.to_string(),
            "F47B23107E5F34B2CE06F562B5C435DF72A533251CB414C51B2B62A8F63A00E4"
        );
        assert_eq!(
            source.to_string(),
            "19D3D919475DEED4696B5D13018151D1AF88B2BD3BCFF048B45031C1F36D1858"
        );
    } else {
        panic!("block.inner was not a receive");
    }
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(json).unwrap(),
        serde_json::to_value(block).expect("Failed to serialize block")
    );
}

#[test]
fn change_block() {
    let json = r#"{
        "type": "change",
        "previous": "F958305C0FF0551421D4ABEDCCF302079D020A0A3833E33F185E2B0415D4567A",
        "representative": "nano_18gmu6engqhgtjnppqam181o5nfhj4sdtgyhy36dan3jr9spt84rzwmktafc",
        "work": "55e5b7a83edc3f4f",
        "signature": "98B4D56881D9A88B170A6B2976AE21900C26A27F0E2C338D93FDED56183B73D19AA5BEB48E43FCBB8FF8293FDD368CEF50600FECEFD490A0855ED702ED209E04"
    }
    "#;
    let block: Block = serde_json::from_str(json).expect("Failed to deserialize block");
    assert_eq!(block.ty(), BlockType::Change);
    assert_eq!(block.header.work, 0x55e5b7a83edc3f4f);
    assert!(block.work_valid(Network::Live));
    assert_eq!(hex::encode_upper(&block.header.signature.to_bytes() as &[u8]), "98B4D56881D9A88B170A6B2976AE21900C26A27F0E2C338D93FDED56183B73D19AA5BEB48E43FCBB8FF8293FDD368CEF50600FECEFD490A0855ED702ED209E04");
    if let BlockInner::Change {
        ref previous,
        ref representative,
    } = block.inner
    {
        assert_eq!(
            previous.to_string(),
            "F958305C0FF0551421D4ABEDCCF302079D020A0A3833E33F185E2B0415D4567A"
        );
        assert_eq!(
            representative.to_string(),
            "nano_18gmu6engqhgtjnppqam181o5nfhj4sdtgyhy36dan3jr9spt84rzwmktafc"
        );
    } else {
        panic!("block.inner was not a change");
    }
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(json).unwrap(),
        serde_json::to_value(block).expect("Failed to serialize block")
    );
}

#[test]
fn open_block() {
    let json = r#"{
        "type": "open",
        "source": "19D3D919475DEED4696B5D13018151D1AF88B2BD3BCFF048B45031C1F36D1858",
        "representative": "nano_1hza3f7wiiqa7ig3jczyxj5yo86yegcmqk3criaz838j91sxcckpfhbhhra1",
        "account": "nano_3kdbxitaj7f6mrir6miiwtw4muhcc58e6tn5st6rfaxsdnb7gr4roudwn951",
        "work": "4ec76c9bda2325ed",
        "signature": "5974324F8CC42DA56F62FC212A17886BDCB18DE363D04DA84EEDC99CB4A33919D14A2CF9DE9D534FAA6D0B91D01F0622205D898293525E692586C84F2DCF9208"
    }
    "#;
    let block: Block = serde_json::from_str(json).expect("Failed to deserialize block");
    assert_eq!(block.ty(), BlockType::Open);
    assert_eq!(block.header.work, 0x4ec76c9bda2325ed);
    assert!(block.work_valid(Network::Live));
    assert_eq!(hex::encode_upper(&block.header.signature.to_bytes() as &[u8]), "5974324F8CC42DA56F62FC212A17886BDCB18DE363D04DA84EEDC99CB4A33919D14A2CF9DE9D534FAA6D0B91D01F0622205D898293525E692586C84F2DCF9208");
    if let BlockInner::Open {
        ref source,
        ref representative,
        ref account,
    } = block.inner
    {
        assert_eq!(
            source.to_string(),
            "19D3D919475DEED4696B5D13018151D1AF88B2BD3BCFF048B45031C1F36D1858"
        );
        assert_eq!(
            representative.to_string(),
            "nano_1hza3f7wiiqa7ig3jczyxj5yo86yegcmqk3criaz838j91sxcckpfhbhhra1"
        );
        assert_eq!(
            account.to_string(),
            "nano_3kdbxitaj7f6mrir6miiwtw4muhcc58e6tn5st6rfaxsdnb7gr4roudwn951"
        );
    } else {
        panic!("block.inner was not a open");
    }
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(json).unwrap(),
        serde_json::to_value(block).expect("Failed to serialize block")
    );
}

#[test]
fn state_block() {
    let json = r#"{
        "type": "state",
        "account": "nano_3oumbo3aztgyn44sm75zkkz6s45ctxyhwfpfscg4o5ibxfer8eq1yrthh1un",
        "previous": "184CF1271B58DA4075CD1329D467345857816EAC5DD4214B0B1CA896DAC704F4",
        "representative": "nano_3rw4un6ys57hrb39sy1qx8qy5wukst1iiponztrz9qiz6qqa55kxzx4491or",
        "balance": "900000000000000000000000000000",
        "link": "1221C72F38AAB95214BBF730BBB5A7792CDC55E5E18F7E4CE747D189B36DE42C",
        "signature": "E7A791BC1AB92C91E3C0FAF37265B3832EE5E3A86070D5AADC734DFFB2788582FE6B2697B7C871BF2ECEC45198C444EA1FF95FCF3922C93B25710B85D0424B0B",
        "work": "fc1a2229b17264ba"
    }
    "#;
    // In this, link is an account, and account is xrb_ prefixed
    let json2 = r#"{
        "type": "state",
        "account": "xrb_3oumbo3aztgyn44sm75zkkz6s45ctxyhwfpfscg4o5ibxfer8eq1yrthh1un",
        "previous": "184CF1271B58DA4075CD1329D467345857816EAC5DD4214B0B1CA896DAC704F4",
        "representative": "nano_3rw4un6ys57hrb39sy1qx8qy5wukst1iiponztrz9qiz6qqa55kxzx4491or",
        "balance": "900000000000000000000000000000",
        "link": "nano_16j3rwqmjcoscacdqxsiqgttgybeujcydrehhs8ggjyjj8spus3eucy56nba",
        "signature": "E7A791BC1AB92C91E3C0FAF37265B3832EE5E3A86070D5AADC734DFFB2788582FE6B2697B7C871BF2ECEC45198C444EA1FF95FCF3922C93B25710B85D0424B0B",
        "work": "fc1a2229b17264ba"
    }
    "#;
    let block: Block = serde_json::from_str(json).expect("Failed to deserialize block");
    assert_eq!(
        serde_json::from_str::<Block>(json2).expect("Failed to deserialize block2"),
        block
    );
    assert_eq!(block.ty(), BlockType::State);
    assert_eq!(block.header.work, 0xfc1a2229b17264ba);
    assert!(block.work_valid(Network::Live));
    assert_eq!(hex::encode_upper(&block.header.signature.to_bytes() as &[u8]), "E7A791BC1AB92C91E3C0FAF37265B3832EE5E3A86070D5AADC734DFFB2788582FE6B2697B7C871BF2ECEC45198C444EA1FF95FCF3922C93B25710B85D0424B0B");
    if let BlockInner::State {
        ref account,
        ref previous,
        ref representative,
        ref balance,
        ref link,
    } = block.inner
    {
        assert_eq!(
            account.to_string(),
            "nano_3oumbo3aztgyn44sm75zkkz6s45ctxyhwfpfscg4o5ibxfer8eq1yrthh1un"
        );
        assert_eq!(
            previous.to_string(),
            "184CF1271B58DA4075CD1329D467345857816EAC5DD4214B0B1CA896DAC704F4"
        );
        assert_eq!(
            representative.to_string(),
            "nano_3rw4un6ys57hrb39sy1qx8qy5wukst1iiponztrz9qiz6qqa55kxzx4491or"
        );
        assert_eq!(*balance, 900000000000000000000000000000);
        assert_eq!(
            hex::encode_upper(&link),
            "1221C72F38AAB95214BBF730BBB5A7792CDC55E5E18F7E4CE747D189B36DE42C"
        );
        assert_eq!(
            Account(*link).to_string(),
            "nano_16j3rwqmjcoscacdqxsiqgttgybeujcydrehhs8ggjyjj8spus3eucy56nba"
        );
    } else {
        panic!("block.inner was not a state");
    }
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(json).unwrap(),
        serde_json::to_value(block).expect("Failed to serialize block")
    );
}

#[test]
fn deser_odd() {
    let json = r#"{
        "type": "state",
        "account": "nano_3oumbo3aztgyn44sm75zkkz6s45ctxyhwfpfscg4o5ibxfer8eq1yrthh1un",
        "previous": "0",
        "representative": "nano_3rw4un6ys57hrb39sy1qx8qy5wukst1iiponztrz9qiz6qqa55kxzx4491or",
        "balance": "900000000000000000000000000000",
        "link": "1221C72F38AAB95214BBF730BBB5A7792CDC55E5E18F7E4CE747D189B36DE42C",
        "signature": "E7A791BC1AB92C91E3C0FAF37265B3832EE5E3A86070D5AADC734DFFB2788582FE6B2697B7C871BF2ECEC45198C444EA1FF95FCF3922C93B25710B85D0424B0B",
        "work": "123"
    }
    "#;
    let block: Block = serde_json::from_str(json).expect("Failed to deserialize block");
    assert_eq!(block.previous(), None);
    assert_eq!(block.header.work, 0x123);
    if let BlockInner::State {
        account,
        previous,
        representative,
        ..
    } = block.inner
    {
        assert_eq!(
            account.to_string(),
            "nano_3oumbo3aztgyn44sm75zkkz6s45ctxyhwfpfscg4o5ibxfer8eq1yrthh1un"
        );
        assert_eq!(previous.0, [0u8; 32]);
        assert_eq!(
            representative.to_string(),
            "nano_3rw4un6ys57hrb39sy1qx8qy5wukst1iiponztrz9qiz6qqa55kxzx4491or"
        );
    } else {
        panic!("block.inner was not a state");
    }
    let json = r#"{
        "type": "state",
        "account": "nano_3oumbo3aztgyn44sm75zkkz6s45ctxyhwfpfscg4o5ibxfer8eq1yrthh1un",
        "previous": "0",
        "representative": "nano_3rw4un6ys57hrb39sy1qx8qy5wukst1iiponztrz9qiz6qqa55kxzx4491or",
        "balance": "900000000000000000000000000000",
        "link": "1221C72F38AAB95214BBF730BBB5A7792CDC55E5E18F7E4CE747D189B36DE42C",
        "signature": "E7A791BC1AB92C91E3C0FAF37265B3832EE5E3A86070D5AADC734DFFB2788582FE6B2697B7C871BF2ECEC45198C444EA1FF95FCF3922C93B25710B85D0424B0B",
        "work": "10000000000000000000000000000"
    }
    "#;
    assert!(serde_json::from_str::<Block>(json).is_err());
    let json = r#"{
        "type": "state",
        "account": "nano_3oumbo3aztgyn44sm75zkkz6s45ctxyhwfpfscg4o5ibxfer8eq1yrthh1un",
        "previous": "0",
        "representative": "nano_3rw4un6ys57hrb39sy1qx8qy5wukst1iiponztrz9qiz6qqa55kxzx4491or",
        "balance": "900000000000000000000000000000",
        "link": "1221C72F38AAB95214BBF730BBB5A7792CDC55E5E18F7E4CE747D189B36DE42C",
        "signature": "E7A791BC1AB92C91E3C0FAF37265B3832EE5E3A86070D5AADC734DFFB2788582FE6B2697B7C871BF2ECEC45198C444EA1FF95FCF3922C93B25710B85D0424B0B",
        "work": "G"
    }
    "#;
    assert!(serde_json::from_str::<Block>(json).is_err());
}

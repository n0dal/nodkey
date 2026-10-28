//! MCP 2026-07-28 conformance for the subset used, strict rejection (AT-04, AT-05), and the
//! call mapping of agent-interface-v1 §2.5, against a fake broker socket W.

mod common;

use common::*;
use serde_json::{Value, json};

fn rpc_code(v: &Value) -> Option<i64> {
    v["error"]["code"].as_i64()
}

fn sc(v: &Value) -> &Value {
    &v["result"]["structuredContent"]
}

fn is_error(v: &Value) -> bool {
    v["result"]["isError"].as_bool().unwrap()
}

/// The text item carries the same JSON as `structuredContent`.
fn text_matches(v: &Value) -> bool {
    let t = v["result"]["content"][0]["text"].as_str().unwrap();
    v["result"]["content"][0]["type"] == "text"
        && serde_json::from_str::<Value>(t).unwrap() == *sc(v)
}

#[tokio::test]
async fn discover_ping_and_ids() {
    let h = harness("disc").await;
    let r = h
        .send(&json!({"jsonrpc":"2.0","id":"a.b-1_c","method":"server/discover","params":{"_meta":meta()}}).to_string())
        .await
        .unwrap();
    assert_eq!(r["id"], "a.b-1_c");
    let res = &r["result"];
    assert_eq!(res["resultType"], "complete");
    assert_eq!(res["supportedVersions"], json!([V]));
    assert_eq!(
        res["capabilities"],
        json!({"tools": {"listChanged": false}})
    );
    assert_eq!(res["ttlMs"], 0);
    assert_eq!(res["cacheScope"], "private");
    assert_eq!(
        res["_meta"]["io.modelcontextprotocol/serverInfo"]["name"],
        "nodkey-mcp"
    );
    let r = h
        .send(&json!({"jsonrpc":"2.0","id":9007199254740991u64,"method":"ping","params":{"_meta":meta()}}).to_string())
        .await
        .unwrap();
    assert_eq!(r["id"], 9007199254740991u64);
    assert_eq!(r["result"], json!({"resultType": "complete"}));
    assert!(h.broker.requests().is_empty());
}

#[tokio::test]
async fn tools_list_is_static_and_omits_resolved_parameters() {
    let h = harness("list").await;
    let line =
        json!({"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"_meta":meta()}}).to_string();
    let r = h.send(&line).await.unwrap();
    assert_eq!(r["result"]["resultType"], "complete");
    let tools = r["result"]["tools"].as_array().unwrap();
    let names: Vec<&str> = tools.iter().map(|t| t["name"].as_str().unwrap()).collect();
    assert_eq!(
        names,
        [
            "payments.support_refund",
            "payments.support_get_order",
            "messages.send",
            "mandate.support_ticket",
            "nodkey.effect_status"
        ],
        "declaration order; undeclared ledger.get_balance absent"
    );
    let props = |i: usize| {
        let mut k: Vec<String> = tools[i]["inputSchema"]["properties"]
            .as_object()
            .unwrap()
            .keys()
            .cloned()
            .collect();
        k.sort();
        k
    };
    assert_eq!(props(0), ["amount_minor", "currency", "order_id"]);
    assert_eq!(props(2), ["body", "customer_sub"]);
    assert!(!props(3).contains(&"customer_email".to_owned()));
    for t in tools {
        assert_eq!(t["inputSchema"]["type"], "object");
        assert_eq!(t["inputSchema"]["additionalProperties"], false);
        assert_eq!(
            t["inputSchema"]["required"].as_array().unwrap().len(),
            t["inputSchema"]["properties"].as_object().unwrap().len()
        );
        assert!(t["outputSchema"].is_object());
    }
    let p = &tools[0]["inputSchema"]["properties"];
    assert_eq!(
        p["order_id"],
        json!({"type":"integer","minimum":0,"maximum":9007199254740991u64})
    );
    assert_eq!(
        p["currency"],
        json!({"type":"string","pattern":"^[A-Z]{3}$"})
    );
    assert_eq!(
        tools[2]["inputSchema"]["properties"]["body"],
        json!({"type":"string","maxLength":256,"pattern":"^[\\x20-\\x7E]*$"})
    );
    // Static: identical on every call.
    assert_eq!(h.send(&line).await.unwrap(), r);
    // No pagination: any cursor is invalid.
    let c = h
        .send(&json!({"jsonrpc":"2.0","id":2,"method":"tools/list","params":{"_meta":meta(),"cursor":"x"}}).to_string())
        .await
        .unwrap();
    assert_eq!(rpc_code(&c), Some(-32602));
}

#[tokio::test]
async fn protocol_version_and_meta_rules() {
    let h = harness("ver").await;
    let with_meta = |m: Value| {
        json!({"jsonrpc":"2.0","id":3,"method":"tools/list","params":{"_meta":m}}).to_string()
    };
    let r = h
        .send(&with_meta(
            json!({"io.modelcontextprotocol/protocolVersion":"2025-11-25",
                                 "io.modelcontextprotocol/clientCapabilities":{}}),
        ))
        .await
        .unwrap();
    assert_eq!(rpc_code(&r), Some(-32022));
    assert_eq!(
        r["error"]["data"],
        json!({"supported":[V],"requested":"2025-11-25"})
    );
    assert_eq!(r["id"], 3);
    for m in [
        json!({"io.modelcontextprotocol/clientCapabilities":{}}),
        json!({"io.modelcontextprotocol/protocolVersion":20260728,"io.modelcontextprotocol/clientCapabilities":{}}),
        json!({"io.modelcontextprotocol/protocolVersion":V}),
        json!({"io.modelcontextprotocol/protocolVersion":V,"io.modelcontextprotocol/clientCapabilities":[]}),
        json!("x"),
    ] {
        assert_eq!(
            rpc_code(&h.send(&with_meta(m.clone())).await.unwrap()),
            Some(-32602),
            "{m}"
        );
    }
    // No params at all.
    let r = h
        .send(r#"{"jsonrpc":"2.0","id":4,"method":"server/discover"}"#)
        .await
        .unwrap();
    assert_eq!(rpc_code(&r), Some(-32602));
    // Extra member in params.
    let r = h
        .send(&json!({"jsonrpc":"2.0","id":5,"method":"server/discover","params":{"_meta":meta(),"x":1}}).to_string())
        .await
        .unwrap();
    assert_eq!(rpc_code(&r), Some(-32602));
    // A tools/call with a bad version never reaches the broker.
    let r = h
        .send(&json!({"jsonrpc":"2.0","id":6,"method":"tools/call","params":{
            "_meta":{"io.modelcontextprotocol/protocolVersion":"2026-01-01","io.modelcontextprotocol/clientCapabilities":{}},
            "name":"payments.support_refund","arguments":{"order_id":101,"amount_minor":2000,"currency":"EUR"}}}).to_string())
        .await
        .unwrap();
    assert_eq!(rpc_code(&r), Some(-32022));
    assert!(h.broker.requests().is_empty());
}

/// AT-04: envelope-level rejections; nothing reaches the broker.
#[tokio::test]
async fn envelope_rejections() {
    let h = harness("env").await;
    let call_ok = call_line(1, "payments.support_get_order", json!({"order_id": 101}));
    let cases: Vec<(String, i64)> = vec![
        (format!("[{call_ok}]"), -32600),
        ("[]".into(), -32600),
        ("42".into(), -32600),
        ("\"x\"".into(), -32600),
        ("{".into(), -32700),
        (
            call_ok.replacen("\"jsonrpc\":\"2.0\"", "\"jsonrpc\":\"1.0\"", 1),
            -32600,
        ),
        (call_ok.replacen("\"jsonrpc\":\"2.0\",", "", 1), -32600),
        (call_ok.replacen("\"id\":1", "\"id\":\"a b\"", 1), -32600),
        (call_ok.replacen("\"id\":1", "\"id\":\"\"", 1), -32600),
        (
            call_ok.replacen("\"id\":1", &format!("\"id\":\"{}\"", "a".repeat(65)), 1),
            -32600,
        ),
        (call_ok.replacen("\"id\":1", "\"id\":-1", 1), -32600),
        (call_ok.replacen("\"id\":1", "\"id\":1.0", 1), -32600),
        (
            call_ok.replacen("\"id\":1", "\"id\":9007199254740992", 1),
            -32600,
        ),
        (call_ok.replacen("\"id\":1", "\"id\":null", 1), -32600),
        (call_ok.replacen("\"id\":1", "\"id\":01", 1), -32700),
        (call_ok.replacen("\"id\":1", "\"id\":1,\"id\":2", 1), -32700),
        (
            call_ok.replacen("\"jsonrpc\"", "\"extra\":1,\"jsonrpc\"", 1),
            -32600,
        ),
        (
            call_ok.replacen(
                "\"method\":\"tools/call\"",
                "\"method\":\"resources/list\"",
                1,
            ),
            -32601,
        ),
        (
            call_ok.replacen("\"method\":\"tools/call\"", "\"method\":\"initialize\"", 1),
            -32601,
        ),
        (
            call_ok.replacen("\"arguments\":{", "\"arguments\":{\"order_id\":1,", 1),
            -32700,
        ),
    ];
    for (line, code) in &cases {
        let r = h.send(line).await.unwrap();
        assert_eq!(rpc_code(&r), Some(*code), "{line}");
    }
    // Invalid UTF-8 and an oversize line.
    let r: Value =
        serde_json::from_str(&h.front.handle_line(b"{\"a\":\"\xff\"}").await.unwrap()).unwrap();
    assert_eq!(rpc_code(&r), Some(-32700));
    let big = format!("{{\"x\":\"{}\"}}", "a".repeat(64 * 1024));
    let r: Value =
        serde_json::from_str(&h.front.handle_line(big.as_bytes()).await.unwrap()).unwrap();
    assert_eq!(rpc_code(&r), Some(-32600));
    // Notifications are not answered.
    assert!(
        h.send(r#"{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":1}}"#)
            .await
            .is_none()
    );
    assert!(h.broker.requests().is_empty(), "nothing reached the broker");
}

/// AT-04 (arguments) and AT-05: tool-level rejections are `isError` + `invalid_argument`; an
/// unknown tool is `-32602`; nothing reaches the broker.
#[tokio::test]
async fn argument_rejections() {
    let h = harness("args").await;
    let refund = "payments.support_refund";
    let raw = |args: &str| {
        format!(
            r#"{{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{{"_meta":{},"name":"{refund}","arguments":{args}}}}}"#,
            meta()
        )
    };
    for a in [
        r#"{"order_id":1.0,"amount_minor":2000,"currency":"EUR"}"#,
        r#"{"order_id":1e3,"amount_minor":2000,"currency":"EUR"}"#,
        r#"{"order_id":-0,"amount_minor":2000,"currency":"EUR"}"#,
        r#"{"order_id":101,"amount_minor":9007199254740992,"currency":"EUR"}"#,
        r#"{"order_id":"101","amount_minor":2000,"currency":"EUR"}"#,
        r#"{"order_id":101,"amount_minor":2000,"currency":"eur"}"#,
        r#"{"order_id":101,"amount_minor":2000,"currency":"EURO"}"#,
        r#"{"order_id":101,"amount_minor":2000}"#,
        r#"{"order_id":101,"amount_minor":2000,"currency":"EUR","x":1}"#,
        // AT-05: resolved, mandate and approver members are not arguments.
        r#"{"order_id":101,"amount_minor":2000,"currency":"EUR","customer_sub":"c42"}"#,
        r#"{"order_id":101,"amount_minor":2000,"currency":"EUR","charge_id":"ch_x"}"#,
        r#"{"order_id":101,"amount_minor":2000,"currency":"EUR","mid":"x"}"#,
        r#"{"order_id":101,"amount_minor":2000,"currency":"EUR","mandate":"x"}"#,
        r#"{"order_id":101,"amount_minor":2000,"currency":"EUR","approver":{"ten":"shop1","sub":"op_bob"}}"#,
        r#"{}"#,
    ] {
        let r = h.send(&raw(a)).await.unwrap();
        assert!(is_error(&r), "{a}");
        assert_eq!(*sc(&r), json!({"error":"invalid_argument"}), "{a}");
        assert!(text_matches(&r));
    }
    // Arguments absent = no members (missing ones) → invalid_argument.
    let r = h
        .send(&json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"_meta":meta(),"name":refund}}).to_string())
        .await
        .unwrap();
    assert_eq!(*sc(&r), json!({"error":"invalid_argument"}));
    // Non-object arguments are a protocol error.
    let r = h.send(&raw("[1]")).await.unwrap();
    assert_eq!(rpc_code(&r), Some(-32602));
    for (tool, a) in [
        (
            "messages.send",
            json!({"customer_sub":"c42","body":"hi","to":"x@evil.example"}),
        ),
        (
            "messages.send",
            json!({"customer_sub":"c42","body":"tab\tnot printable"}),
        ),
        (
            "messages.send",
            json!({"customer_sub":"c42","body":"x".repeat(257)}),
        ),
        (
            "messages.send",
            json!({"customer_sub":"c42","body":"caf\u{e9}"}),
        ),
        (
            "messages.send",
            json!({"customer_sub":"c".repeat(65),"body":"hi"}),
        ),
        (
            "mandate.support_ticket",
            json!({"customer_sub":"c42","currency":"EUR","refund_max_count":3,
            "refund_max_per_call_minor":2500,"refund_max_total_minor":5000,"message_max_count":3,
            "valid_for_s":3600,"customer_email":"x@evil.example"}),
        ),
        ("nodkey.effect_status", json!({"pending_id": pid(1)})),
        (
            "nodkey.effect_status",
            json!({"pending_id": pid(1), "wait_s": 21}),
        ),
        (
            "nodkey.effect_status",
            json!({"pending_id": "short", "wait_s": 0}),
        ),
        (
            "nodkey.effect_status",
            json!({"pending_id": format!("{:0>21}B", "p1"), "wait_s": 0}),
        ),
        (
            "nodkey.effect_status",
            json!({"pending_id": pid(1), "wait_s": 0, "x": 1}),
        ),
    ] {
        let r = h.call(tool, a.clone()).await;
        assert_eq!(*sc(&r), json!({"error":"invalid_argument"}), "{tool} {a}");
        assert!(is_error(&r));
    }
    for tool in [
        "payments.get_card",
        "ledger.get_balance",
        "payments.refund",
        "",
    ] {
        let r = h.call(tool, json!({"order_id": 101})).await;
        assert_eq!(rpc_code(&r), Some(-32602), "{tool}");
    }
    assert!(h.broker.requests().is_empty(), "nothing reached the broker");
}

/// §2.5: write → `effect.propose` with the configured approver, then `effect.status` until
/// settled; every state/awaiting row of the mapping table.
#[tokio::test]
async fn write_mapping_table() {
    let h = harness("map").await;
    let p = "PLACEHOLDER";
    let cases: Vec<(Vec<Value>, Value, bool)> = vec![
        (
            vec![status(p, "PENDING", Some("confirmation"), Value::Null)],
            json!({"status":"pending_confirmation","confirm_url":"https://auth.shop.test/confirm/"}),
            false,
        ),
        (
            vec![
                status(p, "PENDING", Some("mandate"), Value::Null),
                status(p, "APPROVED", None, Value::Null),
                status(p, "EXECUTING", None, Value::Null),
                status(
                    p,
                    "SUCCEEDED",
                    None,
                    json!({"class":"succeeded","receipt_id": pid(99)}),
                ),
            ],
            json!({"status":"succeeded","receipt_id": pid(99)}),
            false,
        ),
        (
            vec![status(
                p,
                "UNKNOWN",
                None,
                json!({"class":"unknown","receipt_id":null}),
            )],
            json!({"status":"outcome_unknown"}),
            false,
        ),
        (
            vec![status(
                p,
                "FAILED",
                None,
                json!({"class":"failed","receipt_id": pid(98), "reason":"provider"}),
            )],
            json!({"status":"failed","receipt_id": pid(98)}),
            true,
        ),
        (
            vec![status(
                p,
                "FAILED",
                None,
                json!({"class":"denied","receipt_id": pid(97)}),
            )],
            json!({"status":"denied","receipt_id": pid(97)}),
            true,
        ),
        (
            vec![status(
                p,
                "DENIED",
                None,
                json!({"class":"denied","receipt_id": pid(96)}),
            )],
            json!({"status":"rejected","receipt_id": pid(96)}),
            true,
        ),
        (
            vec![status(
                p,
                "EXPIRED",
                None,
                json!({"class":"expired","receipt_id": pid(95)}),
            )],
            json!({"status":"expired","receipt_id": pid(95)}),
            true,
        ),
        (
            vec![status(p, "PENDING", Some("mandate"), Value::Null)],
            json!({"status":"in_progress"}),
            false,
        ),
        // Outside the protocol: PENDING without awaiting, unknown state.
        (
            vec![status(p, "PENDING", None, Value::Null)],
            json!({"status":"in_progress"}),
            false,
        ),
    ];
    for (i, (plan, want, err)) in cases.into_iter().enumerate() {
        h.broker.state.lock().unwrap().plan = plan.into();
        let r = h
            .call(
                "payments.support_refund",
                json!({"order_id":101,"amount_minor":2000,"currency":"EUR"}),
            )
            .await;
        let got = sc(&r).clone();
        let id = pid(i as u64 + 1);
        let mut want = want;
        want["pending_id"] = json!(id);
        want["expires_at"] = json!(1_900_000_000u64);
        if let Some(u) = want.get_mut("confirm_url") {
            *u = json!(format!("https://auth.shop.test/confirm/{id}"));
        }
        assert_eq!(got, want, "case {i}");
        assert_eq!(is_error(&r), err, "case {i}");
        assert!(text_matches(&r));
    }
    // The propose request: exactly op, params, approver from configuration.
    let reqs = h.broker.requests();
    let prop = reqs.iter().find(|r| r["op"] == "effect.propose").unwrap();
    assert_eq!(prop["v"], 2);
    assert_eq!(
        prop["args"],
        json!({"op":"payments.support_refund",
               "params":{"order_id":101,"amount_minor":2000,"currency":"EUR"},
               "approver":{"ten":"shop1","sub":"op_ana"}})
    );
    // The broker's confirm_url is never forwarded.
    assert!(!reqs.is_empty());
}

#[tokio::test]
async fn broker_errors_are_codes_only() {
    let h = harness("berr").await;
    for (code, want) in [
        ("invalid_argument", "invalid_argument"),
        ("limit_exceeded", "limit_exceeded"),
        ("operation_not_permitted", "operation_not_permitted"),
        ("something_new", "unavailable"),
    ] {
        h.broker.state.lock().unwrap().propose_error = Some(code.into());
        let r = h
            .call(
                "messages.send",
                json!({"customer_sub":"c42","body":"hello"}),
            )
            .await;
        assert_eq!(*sc(&r), json!({"error": want}));
        assert!(is_error(&r));
        assert!(!r.to_string().contains("FREE TEXT"), "no broker text");
    }
    // Malformed broker replies → unavailable.
    for raw in [
        "not json".to_owned(),
        r#"{"v":2,"id":"wrong","ok":true,"result":{}}"#.to_owned(),
        r#"{"v":1,"id":"mcp-1","ok":true,"result":{}}"#.to_owned(),
    ] {
        {
            let mut g = h.broker.state.lock().unwrap();
            g.propose_error = None;
            g.raw_reply = Some(raw.clone());
        }
        let r = h
            .call(
                "messages.send",
                json!({"customer_sub":"c42","body":"hello"}),
            )
            .await;
        assert_eq!(*sc(&r), json!({"error":"unavailable"}), "{raw}");
    }
}

#[tokio::test]
async fn effect_status_tool_and_reads() {
    let h = harness("st").await;
    // Unknown id → not_found from the broker (T11).
    let r = h
        .call(
            "nodkey.effect_status",
            json!({"pending_id": pid(42), "wait_s": 0}),
        )
        .await;
    assert_eq!(*sc(&r), json!({"error":"not_found"}));
    // A record pending confirmation, then approved and executed while the tool waits.
    h.broker.state.lock().unwrap().plan = vec![
        status("", "PENDING", Some("confirmation"), Value::Null),
        status("", "PENDING", Some("confirmation"), Value::Null),
        status("", "PENDING", Some("confirmation"), Value::Null),
        status("", "PENDING", Some("confirmation"), Value::Null),
        status("", "APPROVED", None, Value::Null),
        status(
            "",
            "SUCCEEDED",
            None,
            json!({"class":"succeeded","receipt_id": pid(7)}),
        ),
    ]
    .into();
    let w = h
        .call(
            "messages.send",
            json!({"customer_sub":"c42","body":"hello"}),
        )
        .await;
    assert_eq!(sc(&w)["status"], "pending_confirmation");
    let id = sc(&w)["pending_id"].as_str().unwrap().to_owned();
    let r = h
        .call(
            "nodkey.effect_status",
            json!({"pending_id": id, "wait_s": 20}),
        )
        .await;
    assert_eq!(sc(&r)["status"], "succeeded");
    assert_eq!(sc(&r)["receipt_id"], pid(7));
    // wait_s 0: one status call, returned as is.
    h.broker.state.lock().unwrap().plan =
        vec![status("", "PENDING", Some("confirmation"), Value::Null)].into();
    let w = h
        .call(
            "messages.send",
            json!({"customer_sub":"c42","body":"hello"}),
        )
        .await;
    let id = sc(&w)["pending_id"].as_str().unwrap().to_owned();
    let before = h.broker.requests().len();
    let r = h
        .call(
            "nodkey.effect_status",
            json!({"pending_id": id, "wait_s": 0}),
        )
        .await;
    assert_eq!(sc(&r)["status"], "pending_confirmation");
    assert_eq!(
        sc(&r)["confirm_url"],
        format!("https://auth.shop.test/confirm/{id}")
    );
    assert_eq!(h.broker.requests().len(), before + 1);

    // Reads: args forwarded as is; result passed through; refusals are codes.
    let order = json!({"order_id":101,"customer_sub":"c42","currency":"EUR","amount_minor":3500,
                       "refunded_minor":0,"status":"captured"});
    h.broker.state.lock().unwrap().read = Some(Ok(order.clone()));
    let r = h
        .call("payments.support_get_order", json!({"order_id": 101}))
        .await;
    assert_eq!(*sc(&r), order);
    assert!(!is_error(&r));
    let last = h.broker.requests().last().unwrap().clone();
    assert_eq!(last["op"], "payments.support_get_order");
    assert_eq!(last["args"], json!({"order_id": 101}));
    h.broker.state.lock().unwrap().read = Some(Err("grant_denied".into()));
    let r = h
        .call("payments.support_get_order", json!({"order_id": 777}))
        .await;
    assert_eq!(*sc(&r), json!({"error":"grant_denied"}));
    // A non-uint number in a broker result is not coerced.
    h.broker.state.lock().unwrap().read = Some(Ok(json!({"order_id": 1.5})));
    let r = h
        .call("payments.support_get_order", json!({"order_id": 101}))
        .await;
    assert_eq!(*sc(&r), json!({"error":"unavailable"}));
}

#[tokio::test]
async fn config_refusals() {
    let ops = nodkey_mcp_front::config::parse_operations(OPS.as_bytes()).unwrap();
    let dir = tmpdir("cfg");
    let base = config_json(&dir, &dir.join("b.sock"), 1, 2);
    let load = |v: &Value| {
        let j = nodkey_mcp_front::json::parse(v.to_string().as_bytes()).unwrap();
        nodkey_mcp_front::config::FrontConfig::from_parts(&j, &ops)
    };
    assert!(load(&base).is_ok());
    let mut bad = Vec::new();
    for (k, v) in [
        ("write_ops", json!(["payments.support_get_order"])),
        ("read_ops", json!(["messages.send"])),
        ("write_ops", json!(["payments.get_card"])),
        ("write_ops", json!(["messages.send", "messages.send"])),
        ("read_ops", json!(["nodkey.effect_status"])),
        ("auth_origin", json!("http://auth.shop.test")),
        ("auth_origin", json!("https://auth.shop.test/x")),
        ("approver", json!({"ten":"shop1","sub":"op ana"})),
        ("approver", json!({"ten":"shop1"})),
        ("agent_uid", json!(-1)),
        ("format", json!("nodkey.mcp-front.v2")),
        ("extra", json!(1)),
    ] {
        let mut c = base.clone();
        c[k] = v;
        bad.push(c);
    }
    let mut missing = base.clone();
    missing.as_object_mut().unwrap().remove("broker_uid");
    bad.push(missing);
    for c in bad {
        assert!(load(&c).is_err(), "{c}");
    }
    // Unknown parameter type in the operations file.
    let bad_ops = OPS.replacen("\"type\":\"uint\"", "\"type\":\"float\"", 1);
    assert!(nodkey_mcp_front::config::parse_operations(bad_ops.as_bytes()).is_err());
    let dup_ops = OPS.replacen(
        "\"op\":\"messages.send\"",
        "\"op\":\"payments.support_refund\"",
        1,
    );
    assert!(nodkey_mcp_front::config::parse_operations(dup_ops.as_bytes()).is_err());
}

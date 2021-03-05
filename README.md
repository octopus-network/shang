## Run a Local Testnet

A simple local testnet consists 4 nodes: 3 validator nodes and 1 full node, the full node is used to expose the RPC interfaces.

Build node-template with command:

```
cargo build --bin node-template
```

Run each of the follwoing commands in different terminals:

```
rm -rf /tmp/alice
./shang/target/debug/node-template \
--base-path /tmp/alice \
--bootnodes /ip4/127.0.0.1/tcp/30334/p2p/12D3KooWHdiAxVd8uMQR1hGWXccidmfCwLqcMpGwR6QcTP6QRMuD \
--bootnodes /ip4/127.0.0.1/tcp/30335/p2p/12D3KooWSCufgHzV4fCwRijfH2k3abrpAJxTKxEvN1FDuRXA2U9x \
--chain=local \
--alice \
--node-key 0000000000000000000000000000000000000000000000000000000000000001 \
--no-telemetry \
--validator \
--execution Native
```

```
rm -rf /tmp/bob
./shang/target/debug/node-template \
--base-path /tmp/bob \
--bootnodes /ip4/127.0.0.1/tcp/30333/p2p/12D3KooWEyoppNCUx8Yx66oV9fJnriXwCcXwDDUA2kj6vnc6iDEp \
--bootnodes /ip4/127.0.0.1/tcp/30335/p2p/12D3KooWSCufgHzV4fCwRijfH2k3abrpAJxTKxEvN1FDuRXA2U9x \
--chain=local \
--bob \
--node-key 0000000000000000000000000000000000000000000000000000000000000002 \
--port 30334 \
--rpc-port 9934 \
--ws-port 9945 \
--no-telemetry \
--validator \
--execution Native

```

```
rm -rf /tmp/charlie
./shang/target/debug/node-template \
--base-path /tmp/charlie \
--bootnodes /ip4/127.0.0.1/tcp/30333/p2p/12D3KooWEyoppNCUx8Yx66oV9fJnriXwCcXwDDUA2kj6vnc6iDEp \
--bootnodes /ip4/127.0.0.1/tcp/30334/p2p/12D3KooWHdiAxVd8uMQR1hGWXccidmfCwLqcMpGwR6QcTP6QRMuD \
--chain=local \
--charlie \
--node-key 0000000000000000000000000000000000000000000000000000000000000003 \
--port 30335 \
--rpc-port 9935 \
--ws-port 9946 \
--no-telemetry \
--validator \
--execution Native
```

```
rm -rf /tmp/full
./shang/target/debug/node-template \
--base-path /tmp/full \
--bootnodes /ip4/127.0.0.1/tcp/30333/p2p/12D3KooWEyoppNCUx8Yx66oV9fJnriXwCcXwDDUA2kj6vnc6iDEp \
--bootnodes /ip4/127.0.0.1/tcp/30334/p2p/12D3KooWHdiAxVd8uMQR1hGWXccidmfCwLqcMpGwR6QcTP6QRMuD \
--bootnodes /ip4/127.0.0.1/tcp/30335/p2p/12D3KooWSCufgHzV4fCwRijfH2k3abrpAJxTKxEvN1FDuRXA2U9x \
--chain=local \
--port 30336 \
--ws-port 9947 \
--ws-external \
--rpc-external \
--rpc-cors all \
--no-telemetry \
--execution Native
```

Then insert keys for offchain workers:

```
curl http://localhost:9933 -H "Content-Type:application/json;charset=utf-8" -d  '{ "jsonrpc":"2.0", "id":1, "method":"author_insertKey", "params": ["oct!", "0x868020ae0687dda7d57565093a69090211449845a7e11453612800b663307246", "0x306721211d5404bd9da88e0204360a1a9ab8b87c66c1bc2fcdd37f3c2222cc20"] }'
curl http://localhost:9934 -H "Content-Type:application/json;charset=utf-8" -d  '{ "jsonrpc":"2.0", "id":1, "method":"author_insertKey", "params": ["oct!", "0x786ad0e2df456fe43dd1f91ebca22e235bc162e0bb8d53c633e8c85b2af68b7a", "0xe659a7a1628cdd93febc04a4e0646ea20e9f5f0ce097d9a05290d4a9e054df4e"] }'
curl http://localhost:9935 -H "Content-Type:application/json;charset=utf-8" -d  '{ "jsonrpc":"2.0", "id":1, "method":"author_insertKey", "params": ["oct!", "0x42438b7883391c05512a938e36c2df0131e088b3756d6aa7a755fbff19d2f842", "0x1cbd2d43530a44705ad088af313e18f80b53ef16b36177cd4b77b846f2a5f07c"] }'
```

Run a frontend app and connect to the full node or observe the state changes through terminal logs.
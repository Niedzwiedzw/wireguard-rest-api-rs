# wireguard-rest-api-rs
## Manipulate wireguard `.conf` files via REST-style interface

## building 
You'll need rust compiler, get it here https://rustup.rs/

```rust
cargo build --release
./target/release/wireguard-rest-api-rs
```

## usage
```rust
wireguard-rest-api-rs --help  # this should get you started

touch ./test-wg0.conf
wireguard-rest-api-rs --port 8000 --host 127.0.0.1 --file_path ./test-wg0.conf --token "secret"
```

### create a new entry

```bash
curl -v -g \
    -H "Accept: */*" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer secret" \
    -X POST \
    -d '{
    "kind": "Peer",
    "values": {
      "PublicKey": "eBtRjue9MBZqpQMi4UWFOY5DXYKa3333rMGpWosKm+YU+UE=",
      "AllowedIPs": "192.0.2.0/24",
      "Endpoint": "162.34.62.31:51820",
      "PersistentKeepAlive": "15"
    }
  }' \
    http://127.0.0.1:8000/

```

### get current entries
```bash

curl -v -g \
    -H "Accept: */*" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer secret" \
    -X GET \
    http://127.0.0.1:8000/
```

### delete an entry
the <ID> part can be retireved from previous request
```bash
curl -v -g \
    -H "Accept: */*" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer secret" \
    -X DELETE \
    http://127.0.0.1:8000/1/
```


## contributions
thanks to https://github.com/Xiretza/ for tremendous help with the parser

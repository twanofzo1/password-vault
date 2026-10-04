# Vault

A minimal, encrypted password manager written in Rust, with a command-line
interface and an optional Tkinter GUI.

Passwords are protected with a master password and stored in a single encrypted
JSON file.

## Features

- **Argon2id** key derivation (OWASP-recommended minimum parameters) for strong
  resistance to brute force.
- **AES-256-GCM** authenticated encryption for every entry.
- A single portable vault file, readable only by the file owner (`0600`) on Unix.
- **Zeroization** of passwords and keys in memory where possible.
- Human-readable and `--json` output for scripting.
- `--stdin` mode so passwords can be piped from scripts or a GUI.
- Optional Tkinter GUI (`gui.py`) that uses the compiled binary.

## Security design

| Layer    | Choice                                                              |
| -------- | ------------------------------------------------------------------- |
| KDF      | Argon2id, `m = 19_456 KiB`, `t = 2`, `p = 1`                        |
| Cipher   | AES-256-GCM with a fresh 12-byte nonce per write                    |
| Salt     | 16 random bytes generated from the OS secure RNG                    |
| Storage  | Base64-encoded JSON: `{ version, salt, nonce, ciphertext }`         |
| Memory   | `zeroize` used for derived keys and plaintext buffers               |

The vault file itself never contains plaintext; only the encrypted ciphertext
and the key-derivation parameters are written to disk.

## Usage

```
vault [--file FILE] [--stdin] [--json] <COMMAND>
```

Global options:

| Option       | Description                                              |
| ------------ | -------------------------------------------------------- |
| `--file`     | Vault file path (default: `vault.json`)                  |
| `--stdin`    | Read passwords from stdin instead of the terminal        |
| `--json`     | Emit JSON for `list` and `get`                           |

Commands:

| Command    | Description                                 |
| ---------- | ------------------------------------------- |
| `init`     | Create a new encrypted vault                 |
| `add`      | Add an entry (`--site`, `--username`)        |
| `get`      | Retrieve an entry's credentials              |
| `list`     | List all entries                             |
| `remove`   | Remove an entry                              |

### Examples

Create a new vault:

```sh
vault init
```

Add an entry (you will be prompted for the master password, then the entry
password):

```sh
vault add --site github --username alice
```

Retrieve credentials:

```sh
vault get github
```

List all entries as JSON:

```sh
vault --file vault.json --json list
```

Feed passwords via stdin (useful from scripts):

```sh
printf 'master\nentry-password\n' | vault --stdin add --site example --username bob
```

## GUI

A Tkinter GUI is provided in [`gui.py`](gui.py). It locates the compiled binary
automatically and defaults to `~/.vault/vault.json`.

```sh
cargo build --release
python3 gui.py
```

The binary can be overridden with the `VAULT_BIN` environment variable.

## File format

The on-disk format is a JSON object with four fields:

```json
{
  "version": 1,
  "salt": "<base64>",
  "nonce": "<base64>",
  "ciphertext": "<base64>"
}
```




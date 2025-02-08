# Hashcat-NTDS-Hash-Match
 A script that quicky matches a user's NTLM hash from NTDS.DIT dump and finds it in the potfile. 


# Build

``` bash
cargo build --release
```

# Usage 

``` bash
./match_hash_to_user <ntds.dit secrestdump file> 
```


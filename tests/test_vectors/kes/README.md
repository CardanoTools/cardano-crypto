# KES Test Vectors

These test vectors are for verifying interoperability with Cardano's Haskell implementation
of Key Evolving Signatures (KES) from `cardano-base/cardano-crypto-class`.

## Generation

The test vectors were generated using the following Haskell code with `cardano-base`:

```haskell
import Cardano.Crypto.Seed
import Cardano.Crypto.DSIGN
import Cardano.Crypto.Hash
import Cardano.Crypto.KES

import Data.Maybe (fromJust)
import qualified Data.ByteString.Char8 as Bytechar
import qualified Data.ByteString as B

main :: IO()
main = let
    seed = mkSeedFromBytes $ Bytechar.pack "test string of 32 byte of lenght"
    kesSk0 = genKeyKES @(Sum0KES Ed25519DSIGN) seed
    kesSk1 = genKeyKES @(Sum1KES Ed25519DSIGN Blake2b_256) seed
    kesSk =  genKeyKES @(Sum6KES Ed25519DSIGN Blake2b_256) seed
    kesSkOneUpdate = fromJust (updateKES () kesSk 0)
    kesSignature = signKES () 0 (Bytechar.pack "test message") kesSk
    kesSkTwoUpdate = fromJust (updateKES () kesSkOneUpdate 1)
    kesSkThreeUpdate = fromJust (updateKES () kesSkTwoUpdate 2)
    kesSkFourUpdate = fromJust (updateKES () kesSkThreeUpdate 3)
    kesSkFiveUpdate = fromJust (updateKES () kesSkFourUpdate 4)
    kesSignatureFive = signKES () 5 (Bytechar.pack "test message") kesSkFiveUpdate

    in do
        B.writeFile "key1.bin" (rawSerialiseSignKeyKES kesSk1)
        B.writeFile "key6.bin" (rawSerialiseSignKeyKES kesSk)
        B.writeFile "key6Sig.bin" (rawSerialiseSigKES kesSignature)
        B.writeFile "key6update1.bin" (rawSerialiseSignKeyKES kesSkOneUpdate)
        B.writeFile "key6update5.bin" (rawSerialiseSignKeyKES kesSkFiveUpdate)
        B.writeFile "key6Sig5.bin" (rawSerialiseSigKES kesSignatureFive)
```

Run the same code with `SumXCompactKES` to generate the compact version test vectors.

## Test Vector Files

### Standard KES
- `key1.hex` - Sum1KES secret key (depth 1)
- `key6.hex` - Sum6KES secret key (depth 6)
- `key6_sig.hex` - Sum6KES signature at period 0
- `key6_update1.hex` - Sum6KES secret key after 1 update
- `key6_sig5.hex` - Sum6KES signature at period 5

### Compact KES
- `compact_key1.hex` - Sum1CompactKES secret key
- `compact_key6.hex` - Sum6CompactKES secret key
- `compact_key6_sig.hex` - Sum6CompactKES signature at period 0
- `compact_key6_update1.hex` - Sum6CompactKES secret key after 1 update
- `compact_key6_sig5.hex` - Sum6CompactKES signature at period 5

## Seed

All keys use the seed: `"test string of 32 byte of lenght"` (32 bytes)
Note: The intentional typo ("lenght" instead of "length") is preserved for compatibility.

Seed as bytes:
```
[116, 101, 115, 116, 32, 115, 116, 114, 105, 110, 103, 32, 111, 102, 32, 51,
 50, 32, 98, 121, 116, 101, 32, 111, 102, 32, 108, 101, 110, 103, 104, 116]
```

## Message

Signatures use the message: `"test message"` (12 bytes)

## Reference

These test vectors match those used in:
- [pallas-crypto](https://github.com/txpipe/pallas/tree/main/pallas-crypto/src/kes/data)
- [cardano-base](https://github.com/IntersectMBO/cardano-base)

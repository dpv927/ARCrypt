# Libreria Kyber

Compilar con kyber512:
```bash
 gcc -o $exec $resources L./libs/kyber/-lpqcrystals_kyber512_ref -lpqcrystals_fips202_ref
```

para kyber512-90s:
```bash
gcc -o $exec $resources L./libs/kyber/ -lpqcrystals_kyber512-90s_ref -lpqcrystals_fips202_ref -lpqcrystals_aes256ctr_ref -lpqcrystals_sha2_ref
```

para kyber768:
```bash
gcc -o $exec $resources L./libs/kyber/ -lpqcrystals_kyber768_ref -lpqcrystals_fips202_ref
```

para kyber768-90s:
```bash
gcc -o $exec $resources L./libs/kyber/-lpqcrystals_kyber768-90s_ref -lpqcrystals_fips202_ref -lpqcrystals_aes256ctr_ref -lpqcrystals_sha2_ref
```

para kyber1024:
```bash
gcc -o $exec $resources L./libs/kyber/ -lpqcrystals_kyber1024_ref -lpqcrystals_fips202_ref
```

para kyber1024-90s:
```bash
gcc -o $exec $resources L./libs/kyber/ -lpqcrystals_kyber1024-90s_ref -lpqcrystals_fips202_ref -lpqcrystals_aes256ctr_ref -lpqcrystals_sha2_ref
```

No olvidar ejecutar el comando:
```bash
export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:./libs/kyber/
```

# ssh-BURNED
Projet isen 

It's a disaster, the private key allowing to connect to all the machines leaked on the DW, fortunately we don't risk anything because it is not complete !

Nous avons eu un challenge où il y a une capture d'écran d'une clé RSA privée mais incomplete.

<img width="528" alt="burned_key (1) (1)" src="https://github.com/user-attachments/assets/3591fb61-14b5-4e5f-ad59-51648d751a09">

Premierementj'ai directement utilisé un outil qui me permet de retranscrire les caracteres du screen-shot en txt. Pour y parvenir j'ai utilisé un outil OCR ( https://www.onlineocr.net/fr/).
On se retrouve alors avec ça.

![image](https://github.com/user-attachments/assets/115aa42e-c053-40d4-82d1-73af20a5efa4)


On peut en déduire grace à l'image que la clé RSA privée comporte 4096 bits et si on génere d'autre clés cela represente 51 lignes.

On va essayer de trouver quelles sont les parties lisibles de la clé RSA.
J'ai remarqué que la clé privé est encodée en PEM(privacy-enhaced mail), elle a comme parametres que c'est toujours encodé dans le meme ordre soit : n ,e ,q ,p ,q ,d (mod p -1), d (mod -1) et q*-1 (mod p).

Donc on en déduit le code présent :

```bash
PrivateKeyInfo ::= SEQUENCE {
   version Version,
   privateKeyAlgorithm AlgorithmIdentifier ,
   privateKey PrivateKey,
   attributes [0] Attributes OPTIONAL
}

RSAPrivateKey ::= SEQUENCE {
  version           Version,
  modulus           INTEGER,  -- n
  publicExponent    INTEGER,  -- e
  privateExponent   INTEGER,  -- d
  prime1            INTEGER,  -- p
  prime2            INTEGER,  -- q
  exponent1         INTEGER,  -- d mod (p-1)
  exponent2         INTEGER,  -- d mod (q-1)
  coefficient       INTEGER,  -- (inverse of q) mod p
  otherPrimeInfos   OtherPrimeInfos OPTIONAL
}
```
Pour pouvoir les retrouver j'ai utilisé un outil qui va me permettre de décoder en base64 puis aprés de me l'encoder en hexadécimal ( 48 par lignes ).
![image](https://github.com/user-attachments/assets/8189a07b-aa1e-458b-a1d1-8e7057566bb8)

Donc pour résumer nous avons notre clé en hexadécimal.
```bash
-----BEGIN RSA PRIVATE KEY-----
3082092a0201000282020100bd387087f686874f6e345a2317dc3eec24ab0ccf6a412a05e5f1040b374b7207be50a014
[                                        Snipped! (x20)                                        ]
a1a4a059c2f4b4fe63bc689ecc202cdf1e0c13929f2ad10a785153f9898f52630a91d11204690282010100e7db92db07
f3385887095316d266e760baa2b9e6cb0f267a4ba17d8c94143726b1338e47de16a15d137324b5e58591908da3aae0ad
6a6bce480736a94d04420c749f2d46a2a00f6cee58e33d515a06f67842bb1a1584a17ab355efd1875d9b2aede3458fff
0f7204b7a327c6ffc01a72c898819667ed6972ecec5a9204c3f4fcd57efd78182440697b9b6e3c9cbf7b18273f7582af
95e245964e1079c0f002c98b45e947bff437412b7cf3beb9d5d84feeab79af41d8894d310add8ffc5eba5d2d915efbc7
485b6dd038c7730360278a6d796ae5a5bfafa8119d29a2705889ad2c5aa4933f7f626446a1e84f7ca7050ed92a0ac020
ea2b980b9d6f9af9325be50282010100d0ec529444a3a18ebd58be52c9d3983fc0b95299f01e044528d3c5f92533a7e6
[                                        Snipped! (x10)                                        ]
0d09c3dfd50282010100a3b81dba5cd391be06b96d63f90f1ca71102e92d02d2b2ebf363892785b4a6250940e5f4503a
29205771772121d2f6f4ea36ee8728c83098e25bd58087e424a3c9f0da26eae6fcdbb1acba1bf756b8793c7c3b41cba4
3458cb2e8f5db7fadd5eb42e0fd563a7e9e8da0bf9438a9b9f5578627bd94ee539eeb40de7dac5d4a213e7d13bd3a7a4
f9a11d05127406ecc00ae3aa8db7234ff892b33c3873adf38d1d1b62dc979be37bc458b16af30fa311d08d85035da193
33e76353e9f9f0c47d5dec83f0322e5fb10026bf002a613b28b3243672b3f6de8466b3bfa08e071dac8f6065acc4fdf2
e99cbe9bee7fac59eecfa752232f4ff22a292ae2e75e6a36ad9f02820100056d864db21a6071724ca2a70091750d7a7a
36f197a227460edd1d311cd179f5ac9cf3502d39dec39647c9275e48800af02ba5675e2a3dfb3c10b524cc972f99e3a3
[                                         Snipped! (x5)                                        ]
-----END RSA PRIVATE KEY-----
```

 Pour continuer on va créer une clé publique en 4096 bits afin de comparer si il y a des similitudes.
 On remarque que les données qu'on cherche commence toujours par 02 82 01 01, c'est décomposer comme :
    - 02 signifie le type de donnée, ( ici un Interger)
    - 82 ce qui signifie que la longueur de la valeur entière sera codée dans les 2 octets suivants
    - 0101 a longueur réelle, dont la valeur entière est 257, ce qui signifie que la valeur entière sera codée dans les 257        octets suivants.

On va décoder les valeurs des données lisibles
```bash
n_upper_bits = 0xbd387087f686874f6e345a2317dc3eec24ab0ccf6a412a05e5f1040b374b7207be50a014
q_upper_bits = 0xd0ec529444a3a18ebd58be52c9d3983fc0b95299f01e044528d3c5f92533a7e6
e = 65537
dq = a3b81dba5cd391be06b96d63f90f1ca71102e92d02d2b2ebf363892785b4a6250940e5f4503a29205771772121d2f6f4ea36ee8728c83098e25bd58087e424a3c9f0da26eae6fcdbb1acba1bf756b8793c7c3b41cba43458cb2e8f5db7fadd5eb42e0fd563a7e9e8da0bf9438a9b9f5578627bd94ee539eeb40de7dac5d4a213e7d13bd3a7a4f9a11d05127406ecc00ae3aa8db7234ff892b33c3873adf38d1d1b62dc979be37bc458b16af30fa311d08d85035da19333e76353e9f9f0c47d5dec83f0322e5fb10026bf002a613b28b3243672b3f6de8466b3bfa08e071dac8f6065acc4fdf2e99cbe9bee7fac59eecfa752232f4ff22a292ae2e75e6a36ad9f
p = 0xdb07f3385887095316d266e760baa2b9e6cb0f267a4ba17d8c94143726b1338e47de16a15d137324b5e58591908da3aae0ad6a6bce480736a94d04420c749f2d46a2a00f6cee58e33d515a06f67842bb1a1584a17ab355efd1875d9b2aede3458fff0f7204b7a327c6ffc01a72c898819667ed6972ecec5a9204c3f4fcd57efd78182440697b9b6e3c9cbf7b18273f7582af95e245964e1079c0f002c98b45e947bff437412b7cf3beb9d5d84feeab79af41d8894d310add8ffc5eba5d2d915efbc7485b6dd038c7730360278a6d796ae5a5bfafa8119d29a2705889ad2c5aa4933f7f626446a1e84f7ca7050ed92a0ac020ea2b980b9d6f9af9325be5


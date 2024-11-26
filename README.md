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

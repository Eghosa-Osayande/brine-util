from main import createUserSignature, getKeyPairFromSignature

privateKey = '11'*32

userSignature = createUserSignature(privateKey,'mainnet')
keyPair = getKeyPairFromSignature(userSignature.signature)

# stark_public_key = keyPair.getPublic().getX().toString('hex')
stark_public_key = hex(keyPair.get_public_key().W.x)

print(stark_public_key)
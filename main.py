from web3 import Web3
from eth_account.messages import encode_defunct
from ecpy.ecdsa import ECDSA,Curve,ECPrivateKey,decode_sig
import hashlib
import hmac

starkEc=Curve.get_curve('stark256')
starkEc.size=starkEc.order.bit_length()

zeroBn =  int('0', 16)

oneBn = int('1', 16)

# Equals 2**251 + 17 * 2**192 + 1.
prime = int(
  '800000000000011000000000000000000000000000000000000000000000001',
  16,
)

# Equals 2**251. This value limits msgHash and the signature parts.
maxEcdsaVal = int(
  '800000000000000000000000000000000000000000000000000000000000000',
  16,
)

def signMsgHash(
    nonce,
    privateKey: str,
    option: str = 'mainnet',  # 'mainnet' | 'testnet' 
):
    userSignature = createUserSignature(privateKey, option)
    return signOrderNonceWithSignature(userSignature, nonce)

def createUserSignature(privateKey: str, option: str):
    msgToBeSigned = "Click sign to verify you're a human - Brine.finance" if (
        option == 'testnet') else 'Get started with Brine. Make sure the origin is https://trade.brine.fi'
    userSignature = signMsg(msgToBeSigned, privateKey)

    return userSignature

def signMsg(msgToBeSigned: str, privateKey: str):
    return Web3().eth.account.sign_message(encode_defunct(text=msgToBeSigned), privateKey)

def signOrderNonceWithSignature(userSignature, nonce):
    keyPair = getKeyPairFromSignature(userSignature.signature)
    return signOrderWithStarkKeys(keyPair, nonce)

def signOrderWithStarkKeys(
  keyPair,
  nonce,
):
  r,s = sign(keyPair, nonce['msg_hash'].replace('0x', ''))
  createOrderBody= {
    "msg_hash": nonce['msg_hash'],
    "signature": {
      "r": hex(r),
      's': hex(s),
    },
    "nonce": nonce['nonce'],
  }
  return createOrderBody    

def getKeyPairFromSignature(signature):
    keySeed = Web3.keccak(text=str(int(signature.hex(), 16)))
    starkEcOrder=starkEc.order
    g=grindKey(keySeed, starkEcOrder)
    return ECPrivateKey(g,starkEc)

def grindKey(keySeed, keyValLimit:int):
    
    # Convert the hexadecimal string to an integer
    sha256EcMaxDigest = int('1 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000'.replace(' ',''), 16)

    # Perform the modulus operation
    maxAllowedVal = sha256EcMaxDigest - (sha256EcMaxDigest % keyValLimit)

    i = 0
    key = hashKeyWithIndex(keySeed, i)
    
    i += 1

    while not(key < maxAllowedVal):
        key = hashKeyWithIndex(keySeed, i)
        i += 1

    result= key % keyValLimit
    # Ensure the result is non-negative
    if result < 0:
        result += keyValLimit

    return result

def hashKeyWithIndex(key, index):
    indexHex = int(hex(index),16)
    sumhex=key.hex() + f"{indexHex:0{2}x}"
    data_bytes = bytes.fromhex(sumhex.lstrip('0x'))

    # # Create a SHA-256 hash object
    sha256_hash = hashlib.sha256()

    # # Update the hash object with the input data
    sha256_hash.update(data_bytes)

    # # Get the hexadecimal representation of the hash
    hash_result_hex = sha256_hash.hexdigest()
    return int(hash_result_hex,16)

def assertInRange(input, lowerBound, upperBound, inputName = ''):
    messageSuffix =  'invalid length' if inputName == '' else f'invalid {inputName} length'
    assert input>lowerBound and input<upperBound ,f'Message not signable, {messageSuffix}.'

def fixMsgHashLen(msgHash):
  # Convert to BN to remove leading zeros.
  msgHash = hex(int(msgHash,16)).lstrip('0x')

  if (len(msgHash) <= 62):
    # In this case, msgHash should not be transformed, as the byteLength() is at most 31,
    # so delta < 0 (see _truncateToN).
    return msgHash
  
  assert len(msgHash) == 63
  # In this case delta will be 4 so we perform a shift-left of 4 bits by adding a zero.

  return msgHash + '0'

def sign(privateKey, msgHash):
    msgHashBN = int(msgHash, 16)
    # Verify message hash has valid length.
    assertInRange(msgHashBN, zeroBn, maxEcdsaVal, 'msgHash')
    fixedMsgHash=fixMsgHashLen(msgHash)
    
    msgBytes=bytes.fromhex(fixedMsgHash)

    def _truncateToN(msg, truncOnly=False):
        msg_len = len(msg)*8
        msg = int.from_bytes(msg, 'big')  
        if msg_len > starkEc.size:
            msg = msg >> (msg_len-starkEc.size)
        if (truncOnly==True and msg>=starkEc.order):
            return msg-starkEc.order;
        else:
            return msg;
        

    def _generateRandomFromKeyAndMsg(key,msg):
        bytez =(starkEc.order.bit_length() + 7) // 8
        
        bkey=key.to_bytes(bytez, byteorder='big')

        msg = _truncateToN(msg)
        msg=msg.to_bytes(bytez, byteorder='big')
        nonce=msg

        return HMAC_DRBG(entropy=bkey+nonce),bytez
    
    gen,bytex=_generateRandomFromKeyAndMsg(privateKey.d,msgBytes)

    ns1 = starkEc.order-1
    
    for i in range(10):
        
        randomK = _truncateToN(gen.generate(bytex) )
        
        
        if(randomK <= 1 or randomK >= ns1):
            continue
        msgSignature=ECDSA().sign_k(msg=msgBytes,pv_key=privateKey,k=randomK)

        r, s = decode_sig(msgSignature)
        # w = s.invm(starkEc.n)
        # Verify signature has valid length.
        # assertInRange(r, oneBn, maxEcdsaVal, 'r')
        # assertInRange(s, oneBn, starkEc.n, 's')
        # assertInRange(w, oneBn, maxEcdsaVal, 'w')
        return r, s

# Implements an HMAC_DRBG (NIST SP 800-90A) based on HMAC_SHA256.
# Supports security strengths up to 256 bits.
# Parameters are based on recommendations provided by Appendix D of NIST SP 800-90A.
class HMAC_DRBG (object):
	def __init__ (self, entropy, requested_security_strength=256, personalization_string=b""):
		if requested_security_strength > 256:
			raise RuntimeError ("requested_security_strength cannot exceed 256 bits.")

		# Modified from Appendix D, which specified 160 bits here
		if len (personalization_string) * 8 > 256:
			raise RuntimeError ("personalization_string cannot exceed 256 bits.")

		if requested_security_strength <= 112:
			self.security_strength = 112
		elif requested_security_strength <= 128:
			self.security_strength = 128
		elif requested_security_strength <= 192:
			self.security_strength = 192
		else:
			self.security_strength = 256

		if (len (entropy) * 8 * 2) < (3 * self.security_strength):
			raise RuntimeError ("entropy must be at least %f bits." % (1.5 * self.security_strength))

		if len (entropy) * 8 > 1000:
			raise RuntimeError ("entropy cannot exceed 1000 bits.")

		self._instantiate (entropy, personalization_string)
	

	# Just for convenience and succinctness
	def _hmac (self, key, data):
		return hmac.new (key, data, hashlib.sha256).digest ()
	

	def _update (self, provided_data=None):
		self.K = self._hmac (self.K, self.V + b"\x00" + (b"" if provided_data is None else provided_data))
		self.V = self._hmac (self.K, self.V)

		if provided_data is not None:
			self.K = self._hmac (self.K, self.V + b"\x01" + provided_data)
			self.V = self._hmac (self.K, self.V)
	

	def _instantiate (self, entropy, personalization_string):
		seed_material = entropy + personalization_string

		self.K = b"\x00" * 32
		self.V = b"\x01" * 32

		self._update (seed_material)
		self.reseed_counter = 1
	
	
	def reseed (self, entropy):
		if (len (entropy) * 8) < self.security_strength:
			raise RuntimeError ("entropy must be at least %f bits." % (self.security_strength))

		if len (entropy) * 8 > 1000:
			raise RuntimeError ("entropy cannot exceed 1000 bits.")

		self._update (entropy)
		self.reseed_counter = 1
	

	def generate (self, num_bytes, requested_security_strength=256):
		if (num_bytes * 8) > 7500:
			raise RuntimeError ("generate cannot generate more than 7500 bits in a single call.")

		if requested_security_strength > self.security_strength:
			raise RuntimeError ("requested_security_strength exceeds this instance's security_strength (%d)" % self.security_strength)

		if self.reseed_counter >= 10000:
			return None

		temp = b""

		while len (temp) < num_bytes:
			self.V = self._hmac (self.K, self.V)
			temp += self.V

		self._update (None)
		self.reseed_counter += 1

		return temp[:num_bytes]

if __name__ == '__main__':
    ethPrivateKey = '11'*32 #replace with privatekey

    orderNonce = {
        "nonce": 27008321,
        "msg_hash": '0x341775ee990a776a5e6e0c74002c12bf01b639a1f2ca882b6e04d2978b13431'
    }

    result=signMsgHash(orderNonce, ethPrivateKey)
    print(result)
    print(result['signature']['r'])
    print(result['signature']['s'])
import datetime
import hashlib
from cryptography.fernet import Fernet
from web3 import Web3

ganache_url= "HTTP://127.0.0.1:7545"
web3= Web3(Web3.HTTPProvider(ganache_url))
print(web3.is_connected())


accounts= web3.eth._accounts()
account1=accounts[0]
account1_private_key='0xaf8e3adb6c68eb5f438d32b4f0e2ecefdfa54ad6d8ba83f225be37000e77a83f'
to_acc=account1
val=1
account2=accounts[1]

nonce=web3.eth.get_transaction_count(account2)



txn = {
    'nonce': nonce,
    'to': account1,
    'value':web3.to_wei(val,'ether'),  # One ether = 1,000,000,000,000,000,000 wei (10e18) 
    'gas': 200000,
    'gasPrice': web3.to_wei('50', 'gwei')
}


signed_tx = web3.eth.account.sign_transaction(txn, account1_private_key)
txn_hash= web3.eth.send_raw_transaction(signed_tx.rawTransaction)







class Block:
    def __init__(self, previous_block_hash, data, timestamp):
        self.previous_block_hash = previous_block_hash
        self.data = data
        self.timestamp = timestamp
        self.hash = self.get_hash()
        # keys
        self.key = Fernet.generate_key()
        self.key_var = Fernet(self.key)
        self.encrypted_data = self.key_var.encrypt(bytes(self.data,'ascii'))
        self.decrypted_data = self.key_var.decrypt(self.encrypted_data)


    @staticmethod
    def create_genesis_block():
        return Block("0", "0", datetime.datetime.now())

    def get_hash(self):
        header_bin = (str(self.previous_block_hash) +
                      str(self.data) +
                      str(self.timestamp))

        inner_hash = hashlib.sha256(header_bin.encode()).hexdigest().encode()
        outer_hash = hashlib.sha256(inner_hash).hexdigest()
        return outer_hash

class Keylist_Block:
    def __init__(self,key,timestamp):
        self.key=key
        self.timestamp = timestamp

    @staticmethod
    def create_genesis_block():
        return Keylist_Block( "0", datetime.datetime.now())

    def get_hash(self):
        header_bin = (str(self.previous_block_hash) +
                      str(self.key) +
                      str(self.timestamp))

        inner_hash = hashlib.sha256(header_bin.encode()).hexdigest().encode()
        outer_hash = hashlib.sha256(inner_hash).hexdigest()
        return outer_hash


# num_blocks_to_add = int(input('\n enter the number of data blocks to add\n'))

block_chain = [Block.create_genesis_block()]

# print("The genesis block has been created.")
print("Hash: %s" % block_chain[0].hash)

for i in range(1, len(accounts)):
    data=accounts[i]
    block_chain.append(Block(block_chain[i-1].hash, data, datetime.datetime.now()))
    print("eccryption #%d completed." % i)
    print("Hash: %s" % block_chain[-1].hash)
    print(block_chain[i].decrypted_data.decode('utf-8'))


# seperating the key from the encrypted data

key_list_chain= [Keylist_Block.create_genesis_block()]

for i in range(1, len(accounts)+1):
    key_list_chain.append(Keylist_Block(block_chain[i-1].key,datetime.datetime.now()))

print('The keylist has be seperated out into a different blockchain')

for i in range(1,len(accounts)): block_chain[i].key=None


def get_data_from_block(block, key):
    decrypted_data = Fernet(key).decrypt(block.encrypted_data)
    return decrypted_data 


for index in range (1, len(accounts)):
            data=get_data_from_block(block_chain[index], key_list_chain[index].key.decode('ascii'))
            print('decrypted data ')
            print(data)
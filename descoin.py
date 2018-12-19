# Implementation of a simplified version of bitcoin
# Des and Xubo's Coin
#


# ==============================================================================
# Libraries
# ==============================================================================
import binascii
import datetime as date
import hashlib
import os.path
import sys
import pickle
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import load_pem_private_key


# ==============================================================================
# Macros
# ==============================================================================
MINING_DIFFICULTY  = 10
BLOCK_PRINT_LENGTH = 20
MINING_BONUS       = 10



# ==============================================================================
# Classes & Structures
# ==============================================================================
class Block:
  def __init__(self, index, previous_hash):


    self.index = index          # block chain index

    # Transaction Details
    self.timestamp = ""         # timestamp at the time of sending
    self.sender = ""            # sender's descoin address
    self.receiver = ""          # receiver's descoin address
    self.signature = ""         # sender's signature
    self.amount = 0             # amount sent

    # Blockchain Information
    self.owner = ""             # owner of this block (miner)
    self.key = 0                # correct key for a correct hash
    self.hash = ""              # hash for the entire block
    self.previous_hash = previous_hash  # obviously


class Kernel:

    def new_wallet(self):
        # This function creates a new key pair for a new wallet
        terminal_clear("New Wallet")

        username = terminal_getname()

        terminal_msg("Generating key pair for your wallet...")

        # generate private/public key pair
        key = rsa.generate_private_key(backend = default_backend(),
                                       public_exponent = 65537,
                                       key_size = 2048)

        # get public key in OpenSSH format
        public_key = key.public_key().public_bytes(serialization.Encoding.OpenSSH,
                                                   serialization.PublicFormat.OpenSSH)

        # get private key in PEM container format
        pem = key.private_bytes(encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption())

        # decode to printable strings
        private_key_str = pem.decode('utf-8')
        public_key_str = public_key.decode('utf-8').split(" ")[1]

        # save wallet information
        file_pem  = open("./wallets/" + username + ".pem", "wb")
        file_addr = open("./wallets/" + username + ".addr", "wb")

        file_pem.write(pem)
        file_addr.write(public_key_str.encode())

        file_pem.close()
        file_addr.close()

        terminal_msg('Your wallet information has been saved. This is your wallet address:')
        terminal_msg(public_key_str)

        return


    def mine_coin(self):
        terminal_clear("Mine Coin")
        username = terminal_getname()
        if checkname(username) == False:
            terminal_msg("This user doesn't have a wallet associated locally.")
            main_menu()
            return
        terminal_msg('Mining starting for user ' + username)

        user_addr = read_user_addr(username)

        # Start mining from latest unverified block
        if verify_chain() > latest_block_number():
            # Every block on the chain is verified. Make a new block to mine
            latest_unverified_block = add_new_block()
        else:
            latest_unverified_block = read_block(verify_chain())



        latest_unverified_block.owner = user_addr.decode()
        magic_key = solve(latest_unverified_block)

        terminal_msg("Congratulations. After " + str(magic_key) +
                     " tries, you've mined a coin on block " +
                     str(latest_unverified_block.index))



        latest_unverified_block.key = magic_key
        latest_unverified_block.hash = block_hash(latest_unverified_block)
        write_block(latest_unverified_block)
        print_block(latest_unverified_block)

        return



    def send_coin(self):
        terminal_clear("Send Coin")

        # Get transaction information
        username = terminal_getname()
        if checkname(username) == False:
            terminal_msg("This user doesn't have a wallet associated locally.")
            main_menu()
        terminal_msg('Sender is now: ' + username)

        user_addr = read_user_addr(username)
        user_pem  = read_user_pem(username)

        terminal_msg('Sending from address: ' + user_addr.decode())
        terminal_msg('Please paste receiver address or username here: ')
        recv_addr_input = sys.stdin.readline().strip()

        # Load receiver addr from username
        if(len(recv_addr_input) != 372):
            recv_addr = read_user_addr(recv_addr_input)
            if recv_addr == b"":
                main_menu()
                return
        else:
            recv_addr = recv_addr_input.encode()


        terminal_msg('Please enter the amount you want to send: ')
        trans_amt = sys.stdin.readline().strip()


        try:
            trans_amt = float(trans_amt)
        except:
            terminal_msg("[ERROR] Amount entered is in illegal format.")
            main_menu()
            return

        # Check if there's enough balance
        bal = get_account_balance(username)
        if bal < trans_amt:
            terminal_msg("[ERROR] You only have " + str(bal) + " left...")
            main_menu()
            return


        # Confirmation
        terminal_msg('=====================================================')
        terminal_msg('PLEASE CONFIRM THE FOLLOWING INFORMATION: ')
        terminal_msg('Sender address: \n' + user_addr.decode())
        terminal_msg('Receiver address: \n' + recv_addr.decode())
        terminal_msg('Transaction amount: \n' + str(trans_amt))
        terminal_msg('=====================================================')
        terminal_msg('Enter "send" to proceed. Type anything else to abort')
        confirmation = sys.stdin.readline().strip()

        if confirmation != "send":
            terminal_msg('ABORTED')
            main_menu()
            return

        # PROCEED, Start writing to a new block and add to the blockchain
        new_block = add_new_block()
        new_block.timestamp =  date.datetime.now()
        new_block.sender = user_addr.decode()
        new_block.receiver = recv_addr.decode()
        new_block.amount = trans_amt
        new_block.signature = sign(str(user_addr) +
                                    str(recv_addr) +
                                    str(trans_amt), user_pem)


        # Write to blockchain
        write_block(new_block)
        print_block(new_block)

        terminal_msg("Transaction completed. Wait for block verification.")
        return


    def account_info(self):
        terminal_clear("Account Informations")
        terminal_msg("Tallying up the blockchain...")
        accounts, verified = tally_chain()
        terminal_msg("Total transactions:")
        print_accounts(accounts)
        terminal_msg("Verified transactions:")
        print_accounts(verified)




# ==============================================================================
# Functions
# ==============================================================================

def print_accounts(accounts):
    terminal_msg("---------------------------------------")
    terminal_msg("           USERNAME        |  BALANCE  ")

    for root, dirs, files in os.walk("./wallets/"):
        user_list = [filename.split(".")[0] for filename in files]
        user_list = list(set(user_list))

    for acc in user_list:
        if acc != "":
            addr = read_user_addr(acc)
            addr = addr.decode()
            if addr not in accounts:
                accounts[addr] = 0
            terminal_msg("   " + trim(acc) + " | " + str(accounts[addr]))

    terminal_msg("---------------------------------------\n")


def get_account_balance(username):
    # This function tally up the blockchain and calculate a given user's balance
    accounts, verified = tally_chain()
    user_addr = read_user_addr(username)
    user_addr = user_addr.decode()

    if user_addr not in verified:
        # user do NOT exist, balance is default to 0
        return 0
    else:
        # return verified balance
        return verified[user_addr]

def tally_chain():
    # This function goes through the entire block chain to tally up balances
    accounts = {}
    verified = {}

    # Iterate through the block chain
    for i in range(latest_block_number()+1):
        b = read_block(i)

        # only update the verified accounts on verified list
        if block_is_verified(i) == True:
            # Update sender account
            if b.sender not in verified:
                verified[b.sender] = -b.amount
            else:
                verified[b.sender] = verified[b.sender] - b.amount

            # Update receiver account
            if b.receiver not in verified:
                verified[b.receiver] = b.amount
            else:
                verified[b.receiver] = verified[b.receiver] + b.amount

        # Update sender account
        if b.sender not in accounts:
            accounts[b.sender] = -b.amount
        else:
            accounts[b.sender] = accounts[b.sender] - b.amount

        # Update receiver account
        if b.receiver not in accounts:
            accounts[b.receiver] = b.amount
        else:
            accounts[b.receiver] = accounts[b.receiver] + b.amount


        if b.owner != "":
            # Update miner's account
            if b.owner not in accounts:
                accounts[b.owner] = MINING_BONUS
            else:
                accounts[b.owner] = accounts[b.owner] + MINING_BONUS
            # Update miner's account
            if b.owner not in verified:
                verified[b.owner] = MINING_BONUS
            else:
                verified[b.owner] = verified[b.owner] + MINING_BONUS

    return accounts, verified


def verify_chain():
    # This function verifies the integrity of the whole blockchain
    # and return the index of the earliest unverified block
    i = 0
    while True:
        if block_is_verified(i) == False:
            return i
        i = i + 1


def count_hash_zeros(hash):
    # This function counts how many zeros there are in front of the binary hash
    bin_hash = str(bin(int(hash, 16)))[2:]
    counter = 256 - len(bin_hash) # compensate for omitted zeros
    return counter


def solve(block):
    # This function essentially try to find the right key for the block
    magic_key = 0
    while True:
        block.key = magic_key
        hash = block_hash(block)

        if count_hash_zeros(hash) >= MINING_DIFFICULTY:
            return magic_key
            break

        magic_key = magic_key + 1



def sign(message, pem):
    signature = pem.sign(message.encode(),
                                 padding.PSS(
                                    mgf=padding.MGF1(hashes.SHA256()),
                                    salt_length=padding.PSS.MAX_LENGTH
                                 ),
                                 hashes.SHA256())
    return signature

def add_new_block():
    previous_block_index = latest_block_number()
    previous_hash = read_hash(previous_block_index)
    new_block = Block(previous_block_index + 1, previous_hash)
    return new_block


def block_is_verified(index):
    # If every block on the chain is verified, return the next future block
    if index > latest_block_number():
        return False

    # return True or False for Verified and Unverified
    b = read_block(index)

    if b.hash == "":
        return False
    else:
        # verify hash integrity
        h = block_hash(b)
        return h == b.hash


def block_hash(block):
    sha = hashlib.sha256()
    hash_src = str(block.index) + \
               str(block.timestamp) +\
               str(block.sender) +\
               str(block.receiver) +\
               str(block.signature) +\
               str(block.amount) +\
               str(block.owner) +\
               str(block.key) +\
               str(block.previous_hash)
    sha.update(hash_src.encode())
    return sha.hexdigest()


def mine(block, user_addr):
    # this function tries to verify the block by finding the right key
    block.owner = user_addr
    block.key = 0

def read_user_pem(username):
    file_pem = open("./wallets/" + username + ".pem", "rb")
    pem = file_pem.read()
    key = load_pem_private_key(pem, password = None, backend=default_backend())
    file_pem.close()
    return key


def read_user_addr(username):
    try:
        file_addr = open("./wallets/" + username + ".addr", "rb")
        addr = file_addr.read()
        file_addr.close()
        return addr
    except:
        terminal_msg("[ERROR] This username doesn't exist locally.")
        return b""

def read_hash(index):
    # return the hash from a previous block, return empty string if not verified
    block_read = open("./blocks/" + str(index) + ".block","rb")
    b = pickle.load(block_read)
    block_read.close()
    return b.hash

def read_block(index):
    # return the whole block
    block_read = open("./blocks/" + str(index) + ".block","rb")
    b = pickle.load(block_read)
    block_read.close()
    return b


def trim(s):
    # this function trims the given string down to len
    s = str(s)
    if len(s) <= BLOCK_PRINT_LENGTH:
        space = " " * (BLOCK_PRINT_LENGTH - len(s) + 3)
        if s == "":
            return "N/A                    "
        else:
            return s + space
    else:
        return s[:BLOCK_PRINT_LENGTH] + "..."

def print_block(b):
    # print the whole block
    terminal_msg("========= BLOCK " + str(b.index) + " =========")
    terminal_msg("Verified:   " + str(block_is_verified(b.index)))
    terminal_msg("Owner:      " + trim(b.owner))
    terminal_msg("Key:        " + trim(b.key))
    terminal_msg("Hash:       " + trim(b.hash))
    terminal_msg("Prev Hash:  " + trim(b.previous_hash))
    terminal_msg("\n   - Transaction Details - ")
    terminal_msg("Sender:     " + trim(b.sender))
    terminal_msg("Receiver:   " + trim(b.receiver))
    terminal_msg("Signature:  " + trim(b.signature))
    terminal_msg("Amount:     " + trim(b.amount))
    terminal_msg("Timestamp:  " + trim(b.timestamp))
    terminal_msg("=============================")


def write_block(block):
    # write a given block to the block chain
    block_write = open("./blocks/" + str(block.index) + ".block","wb")
    pickle.dump(block, block_write)
    block_write.close()
    if latest_block_number() < block.index:
        update_meta(block.index)
    return 0


def checkname(username):
    # This function check if a given username has a wallet associated
    return os.path.exists("./wallets/" + username + ".addr")


def hash(str):
    m = hashlib.sha256()
    m.update(str.encode())
    return m.hexdigest()


def terminal_getname():
    terminal_msg("Please enter your name: (letters only)")
    while True:
        username = sys.stdin.readline().strip()
        if username.isalpha() == True:
            break
        terminal_msg("[Error] English letters only please.")
    return username


def terminal_clear(msg = ""):
    # This function clears the terminal page
    sys.stdout.write(chr(27) + "[2J")
    sys.stdout.write(chr(27) + "[1;1f")
    if msg != "":
        terminal_msg(msg)


def terminal_msg(msg):
    # This function prints to standard output
    sys.stdout.write(msg+"\n")


def create_starting_block():
  # Manually construct a block with
    b = Block(0, "STARTING HASH FOR DESCOIN")
    b.hash = block_hash(b)
    write_block(b)
    meta = open("./blocks/meta.info","w")
    meta.write("0")
    meta.close()

def latest_block_number():
    # This function returns the index number of the latest block (tail)
    meta = open("./blocks/meta.info","r")
    number = int(meta.readline().strip())
    meta.close()
    return number

def update_meta(index):
    # This function writes the index number of the latest block (tail)
    meta = open("./blocks/meta.info","w")
    meta.write(str(index))
    meta.close()

# This function lists a several choices for the user to choose from
def terminal_choose(choices,kernel):
    terminal_msg("[Type in the number of the action and press ENTER]")
    for i in range(len(choices)):
        terminal_msg(" " + str(i+1) + " - " + choices[i][0])
    while True:
        c = sys.stdin.readline()
        try:
            c = int(c)
            if c <= len(choices) and c > 0:
                break;
            else:
                terminal_msg("[Error] Number out of range. Please try again.")
        except:
            terminal_msg("[Error] Not a number. Please try again.")
    terminal_clear()
    getattr(kernel, choices[c-1][1])()


def main_menu():
    kernel = Kernel()
    menu_start = [("Make New Wallet","new_wallet"),
                  ("Mine Coins","mine_coin"),
                  ("Send Coins","send_coin"),
                  ("Account Information","account_info")]
    terminal_choose(menu_start,kernel)


def init_chain():
    if os.path.exists("./blocks/0.block") == False \
    or os.path.exists("./blocks/meta.info") == False:
        terminal_msg("Initializing Chain...")
        update_meta(0)
        create_starting_block()

def main():
    init_chain()
    terminal_clear()
    terminal_msg("Welcome to Desmond and Xubo's cryptocurrency.")
    while True:
        main_menu()

main()

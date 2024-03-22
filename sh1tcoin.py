import random

import rsa, sys, hashlib, binascii, os, datetime, math

class sh1tcoin:

    def __init__(self):
        self.name = "sh1tcoin"
        self.mempool = "mempool.txt"

    # returns name of coin
    def __str__(self):
        return self.name

    #--- helper methods provided here https://aaronbloomfield.github.io/ics/hws/cryptocurrency/sample.py.html ---#
    @staticmethod
    def hashFile(filename):
        h = hashlib.sha256()
        with open(filename, 'rb', buffering=0) as f:
            for b in iter(lambda: f.read(128 * 1024), b''):
                h.update(b)
        return h.hexdigest()

    # given an array of bytes, return a hex reprenstation of it
    @staticmethod
    def bytesToString(data):
        return binascii.hexlify(data)

    # given a hex reprensetation, convert it to an array of bytes
    @staticmethod
    def stringToBytes(hexstr):
        return binascii.a2b_hex(hexstr)

    # Load the wallet keys from a filename
    @staticmethod
    def loadWallet(filename):
        with open(filename, mode='rb') as file:
            keydata = file.read()
        privkey = rsa.PrivateKey.load_pkcs1(keydata)
        pubkey = rsa.PublicKey.load_pkcs1(keydata)
        return pubkey, privkey

    # save the wallet to a file
    @staticmethod
    def saveWallet(pubkey, privkey, filename):
        # Save the keys to a key format (outputs bytes)
        pubkeyBytes = pubkey.save_pkcs1(format='PEM')
        privkeyBytes = privkey.save_pkcs1(format='PEM')
        # Convert those bytes to strings to write to a file (gibberish, but a string...)
        pubkeyString = pubkeyBytes.decode('ascii')
        privkeyString = privkeyBytes.decode('ascii')
        # Write both keys to the wallet file
        with open(filename, 'w') as file:
            file.write(pubkeyString)
            file.write(privkeyString)
        return
    #--- end of provided helper methods ---#

    @staticmethod
    def getTimestamp():
        time = datetime.datetime.now()
        timestamp = time.strftime("%a %b %d %H:%M:%S%Z EDT %Y")
        return timestamp

    @staticmethod
    def getHighestBlock():
        exists = True
        i = -1
        while exists:
            i += 1
            currentblock = "block_" + str(i + 1) + ".txt"
            exists = os.path.exists(currentblock)
        return i

        # creates the genesis block of the blockchain
    def genesis(self):
        filename = "block_0.txt"
        with open(filename, "w") as f:
            f.write('...And on the 0th day, Gabe said, "let there be sh1tcoin!"')
        print(f"Gensis block created in '{filename}'")

    # generates a new wallet with passed filename
    def generate(self, filename):
        # https://stuvel.eu/python-rsa-doc/usage.html#generating-keys
        (pubkey, privkey) = rsa.newkeys(1024)
        self.saveWallet(pubkey,privkey, filename)
        tag = self.tag(filename)
        print(f"New wallet generated in '{filename}' with tag {tag}")

    # gets tag (first 16 chars of public key) of existing wallet
    def tag(self, filename): # called w/ -address
        (pubkey, privkey) = self.loadWallet(filename)
        pubkeyBytes = pubkey.save_pkcs1(format='PEM')
        pubkeyString = pubkeyBytes.decode('ascii')
        pubkeyString = pubkeyString.replace("-----BEGIN RSA PUBLIC KEY-----","")
        pubkeyString = pubkeyString.replace("-----END RSA PUBLIC KEY-----", "")
        pubkeyString = pubkeyString.replace("\n", "")
        tag = hashlib.sha256(pubkeyString.encode('ascii'))
        tag = tag.hexdigest()[0:16]
        return tag

    def fund(self, destination, amount, tsfile, source):
        # https://pynative.com/python-datetime-format-strftime/#:~:text=Use%20datetime.,hh%3Amm%3Ass%20format

        # writing the transaction statement file
        timestamp = self.getTimestamp()
        tsfile = open(tsfile, 'w')
        tsfile.write(f"From: {source}\n")
        tsfile.write(f"To: {destination}\n")
        tsfile.write(f"Amount: {amount}\n")
        tsfile.write(f"Date: {timestamp}\n")
        print(f"Funded Wallet {destination} with {amount} sh1tcoins on {timestamp}")
        #transaction statements from fund command dont need signature
        #and they dont need verification so they can just go straight to mempool
        with open(self.mempool, 'a') as f:
            f.write(f"{source} transferred {amount} to {destination} on {timestamp}\n")


    def transfer(self,source,destination,amount,tsfile):

        # this command only writes a transaction statement. no mempool
        timestamp = self.getTimestamp()
        tsfilename = tsfile
        tsfile = open(tsfile, 'w')
        tsfile.write(f"From: {self.tag(source)}\n")
        tsfile.write(f"To: {destination}\n")
        tsfile.write(f"Amount: {amount}\n")
        tsfile.write(f"Date: {timestamp}\n")
        tsfile.close()

        print(f"Transferred {amount} from {source} to {destination} and the statement to '{tsfilename}' on {timestamp}")
        # hashing file, encrypting w/ private key, and appending to transaction statement
        hashed = self.stringToBytes(self.hashFile(tsfilename)) #hasing file as message

        # if tsfilename == "03-alice-to-bob.txt":
        #     print(hashed)

        privkey = self.loadWallet(source)[1] # getting private key
        signature = rsa.sign(hashed, privkey, 'SHA-256').hex()
        tsfile = open(tsfilename, 'a')
        tsfile.write("\n")
        tsfile.write(signature)
        tsfile.close()

    def balance(self, source): # source is tag of sender
        balance = 0
        for i in range(1, self.getHighestBlock()+1):
            currentblock = "block_" + str(i) + ".txt"
            with open(currentblock) as file:
                for line in file:
                    line = line.split(" ")
                    if len(line) > 2:
                        if line[0]==source:
                            balance -= int(line[2])
                        elif line[4]==source:
                            balance += int(line[2])

        with open("mempool.txt") as file:
            for line in file:
                line = line.split(" ")
                if line[0]==source:
                    balance -= int(line[2])
                elif line[4]==source:
                    balance += int(line[2])

        return balance

    def verify(self, walletfn, tsfile):
        file = open(tsfile, 'r')
        lines = file.readlines()
        valid = False #can just be false; fund things added to mempool in fund

        # 1) check signature on TSFs not from fund()
        if(lines[0][6:10] != "Gabe"):
            # getting message
            fourlines = lines[0:4]
            with open("a.txt", 'w') as file:
                for line in fourlines:
                    file.write(line)
            message = self.stringToBytes(self.hashFile("a.txt"))
            # if tsfile == "03-alice-to-bob.txt":
            #     print(message)

            # getting signature
            signature = self.stringToBytes(lines[5])

            # getting public key
            pubkey = self.loadWallet(walletfn)[0]

            # according to this: https://stuvel.eu/python-rsa-doc/usage.html#signing-and-verification
            # successful verification returns the hash algorithm, failure raises exception
            try:
                rsa.verify(message,signature,pubkey)
                valid = True
            except rsa.VerificationError:
                valid = False

        # 2) get balance using pubkey tag
        tag = self.tag(walletfn)
        balance = self.balance(tag)
        amount = lines[2].split(" ")[1]

        # 3) add to mempool as transaction line!
        if balance >= int(amount) and valid:
            with open(self.mempool, 'a') as f:
                source = lines[0].split(" ")[1].strip("\n")
                amount = lines[2].split(" ")[1].strip("\n")
                destination = lines[1].split(" ")[1].strip("\n")
                timestamp = " ".join(lines[3].split(" ")[1::]).strip("\n") # thx python
                f.write(f"{source} transferred {amount} to {destination} on {timestamp}\n")
                print(f"The transaction in file {tsfile} with wallet {walletfn} is valid, and was written to mempool")

    def mine(self, difficulty):

        # block can be mined if when adding nonce it has value below
        # hash of block without nonce with x = difficulty leading 0's

        block = "block_" + str(self.getHighestBlock() + 1) + ".txt"
        hashprev = "block_" + str(self.getHighestBlock()) + ".txt"
        mempool = open("mempool.txt", 'r')
        mempoollines = mempool.readlines()
        mempool.close()
        nonce = 0

        with open(block, "w") as f:
            f.write(self.hashFile(hashprev) + '\n')
            f.write('\n')
            for line in mempoollines:
                f.write(line)
            f.write('\n')
            f.write("nonce: " + str(nonce))

        valid = False
        j = 0

        while valid == False:
            nonce += 1
            #forgot to add nonce to the file lol
            blockfile = open(block, 'r')
            blockfilelines = blockfile.readlines()[:-1]
            blockfile.close()
            with open(block, 'w') as f:
                for line in blockfilelines:
                    f.write(line)
                f.write("nonce: " + str(nonce))
            value = self.hashFile(block)
            # print(f"mining attempt {j} with nonce {nonce} and value {value}")
            # j += 1
            for i in range(int(difficulty)):
                if value[i] != "0":
                    break
                if i == int(difficulty)-1 and value[i] == "0":
                    valid = True

        with open("mempool.txt", "w") as f:
            f.write("")

    def validate(self):
        valid = True
        for i in range(self.getHighestBlock() , 0, -1):
            currentblock = "block_" + str(i) + ".txt"
            prevblock = "block_" + str(i-1) + ".txt"
            hashprevblock = self.hashFile(prevblock)
            file = open(currentblock)
            currentblocklinezero = file.readlines()[0].strip('\n')
            file.close()
            if currentblocklinezero != hashprevblock:
                valid = False
                break

        return valid


def main():
    sc = sh1tcoin()
    i = 1
    while i < len(sys.argv):
        if sys.argv[i] == "name":
            print(sc)
            i += 1

        elif sys.argv[i] == "genesis":
            sc.genesis()
            i += 1

        elif sys.argv[i] == "generate":
            filename = sys.argv[i+1]
            sc.generate(filename)
            i += 2

        elif sys.argv[i] == "address":
            filename = sys.argv[i+1]
            print(sc.tag(filename))
            i += 2

        elif sys.argv[i] == "fund":
            destination = sys.argv[i+1] # desintation wallet tag
            amount = sys.argv[i+2] # amount to send
            tsfile = sys.argv[i+3] # file name to save transaction statement to
            source = "Gabe" # special case ID for fund method
            sc.fund(destination, amount, tsfile, source)
            i += 4

        elif sys.argv[i] == "transfer":
            source = sys.argv[i+1] # source wallet FILE NAME
            destination = sys.argv[i+2] # destination wallet TAG
            amount = sys.argv[i+3]
            tsfile = sys.argv[i+4]
            sc.transfer(source,destination,amount,tsfile)
            i += 5

        elif sys.argv[i] == "balance":
            source = sys.argv[i+1]
            print(sc.balance(source))
            i += 2

        elif sys.argv[i] == "verify":
            walletfn = sys.argv[i+1]
            tsfile = sys.argv[i+2]
            sc.verify(walletfn, tsfile)
            i += 3

        elif sys.argv[i] == "mine":
            difficulty = sys.argv[i+1]
            sc.mine(difficulty)
            i += 2

        elif sys.argv[i] == "validate":
            print(sc.validate())
            i += 1

if __name__ == "__main__":
    main()


package proj2

// You MUST NOT change what you import.  If you add ANY additional
// imports it will break the autograder, and we will be Very Upset.

import (
	// You neet to add with
	// go get github.com/nweaver/cs161-p2/userlib
	"github.com/nweaver/cs161-p2/userlib"

	// Life is much easier with json:  You are
	// going to want to use this so you can easily
	// turn complex structures into strings etc...
	"encoding/json"

	// Likewise useful for debugging etc
	"encoding/hex"

	// UUIDs are generated right based on the crypto RNG
	// so lets make life easier and use those too...
	//
	// You need to add with "go get github.com/google/uuid"
	"github.com/google/uuid"

	// Useful for debug messages, or string manipulation for datastore keys
	"strings"

	// Want to import errors
	"errors"

	// optional
	_ "strconv"

	// if you are looking for fmt, we don't give you fmt, but you can use userlib.DebugMsg
	// see someUsefulThings() below
)

// This serves two purposes: It shows you some useful primitives and
// it suppresses warnings for items not being imported
func someUsefulThings() {
	// Creates a random UUID
	f := uuid.New()
	userlib.DebugMsg("UUID as string:%v", f.String())

	// Example of writing over a byte of f
	f[0] = 10
	userlib.DebugMsg("UUID as string:%v", f.String())

	// takes a sequence of bytes and renders as hex
	h := hex.EncodeToString([]byte("fubar"))
	userlib.DebugMsg("The hex: %v", h)

	// Marshals data into a JSON representation
	// Will actually work with go structures as well
	d, _ := json.Marshal(f)
	userlib.DebugMsg("The json data: %v", string(d))
	var g uuid.UUID
	json.Unmarshal(d, &g)
	userlib.DebugMsg("Unmashaled data %v", g.String())

	// This creates an error type
	userlib.DebugMsg("Creation of error %v", errors.New(strings.ToTitle("This is an error")))

	// And a random RSA key.  In this case, ignoring the error
	// return value
	var pk userlib.PKEEncKey
        var sk userlib.PKEDecKey
	pk, sk, _ = userlib.PKEKeyGen()
	userlib.DebugMsg("Key is %v, %v", pk, sk)
}

// Helper function: Takes the first 16 bytes and
// converts it into the UUID type
func bytesToUUID(data []byte) (ret uuid.UUID) {
	for x := range ret {
		ret[x] = data[x]
	}
	return
}

// Helper function: Tests byte slice equality
func testEq(a, b []byte) bool {
    if (a == nil) != (b == nil) { 
        return false; 
    }
    if len(a) != len(b) {
        return false
    }
    for i := range a {
        if a[i] != b[i] {
            return false
        }
    }
    return true
}

// The structure definition for a user record
type User struct {
	Username string
	SignKey userlib.DSSignKey
	DecKey userlib.PKEDecKey
	FatKey []byte // containing MAC key, symmetric encryption key, etc
	RootFiles map[string] uuid.UUID
	FileKeys.map[string] []byte
	// You can add other fields here if you want...
	// Note for JSON to marshal/unmarshal, the fields need to
	// be public (start with a capital letter)
}

type File struct {
	NameLength int
	FileData []byte
	Mac []byte
}

type RootFile struct {
	Files []uuid.UUID
}

// This creates a user.  It will only be called once for a user
// (unless the keystore and datastore are cleared during testing purposes)

// It should store a copy of the userdata, suitably encrypted, in the
// datastore and should store the user's public key in the keystore.

// The datastore may corrupt or completely erase the stored
// information, but nobody outside should be able to get at the stored
// User data: the name used in the datastore should not be guessable
// without also knowing the password and username.

// You are not allowed to use any global storage other than the
// keystore and the datastore functions in the userlib library.

// You can assume the user has a STRONG password
func InitUser(username string, password string) (userdataptr *User, err error) {
	var userdata User

	//convert username and password to byte arrays
	unbyte := []byte(username)
	pwbyte := []byte(password)

	// generate decryption (priv) & encryption key for asymmetric encryption
	enckey, deckey, err0 := userlib.PKEKeyGen()
	if err0 != nil {
		return nil, err0
	}

	// generate signing (priv) & verifying key for digital signatures
	signkey, verkey, err1 := userlib.DSKeyGen()
	if err1 != nil {
		return nil, err1
	}

	// generate a fat key and split it into MAC and symmetric encryption keys (priv)
	fatkey := userlib.Argon2Key(pwbyte, unbyte, 32)
	mackey := fatkey[:16]
	symkey := fatkey[16:32]

	// put private keys in userdata
	userdata.Username = username
	userdata.DecKey = deckey
	userdata.SignKey = signkey
	userdata.FatKey = fatkey
	userdata.RootFiles = make(map[string] uuid.UUID)
	userdata.FileKeys = make(map[string] []byte)

	// generate iv and encrypt userdata struct
	iv := userlib.RandomBytes(16)
	userjson, err2 := json.Marshal(userdata)
	if err2 != nil {
		return nil, err2
	}
	cipher := userlib.SymEnc(symkey, iv, userjson)

	// make uuid and store struct in datastore
	macbytes, err3 := userlib.HMACEval(mackey, unbyte)
	if err3 != nil {
		return nil, err3
	}
	uuid, _ := uuid.FromBytes(macbytes[:16])
	userlib.DatastoreSet(uuid, cipher)

	// store public key in keystore
	userlib.KeystoreSet(username + "_enc", enckey)
	userlib.KeystoreSet(username + "_ver", verkey)

	return &userdata, nil
}

// This fetches the user information from the Datastore.  It should
// fail with an error if the user/password is invalid, or if the user
// data was corrupted, or if the user can't be found.
func GetUser(username string, password string) (userdataptr *User, err error) {
	var userdata User
	userdataptr = &userdata

	//convert username and password to byte arrays
	unbyte := []byte(username)
	pwbyte := []byte(password)

	// generate the fat key and get MAC and symmetric encryption keys
	fatkey := userlib.Argon2Key(pwbyte, unbyte, 32)
	mackey := fatkey[:16]
	symkey := fatkey[16:32]

	// find uuid
	macbytes, err := userlib.HMACEval(mackey, unbyte)
	if err != nil {
		return nil, err
	}
	uuid, _ := uuid.FromBytes(macbytes[:16])

	// fetch user with uuid from datastore
	encryptedjson, ok := userlib.DatastoreGet(uuid)
	if !ok {
		return nil, errors.New(strings.ToTitle("Error getting user"))
	}

	// decrypt
	userjson := userlib.SymDec(symkey, encryptedjson)
	json.Unmarshal(userjson, userdataptr)

	// integrity check
	if !testEq(userdata.FatKey, fatkey) {
		return nil, errors.New(strings.ToTitle("Integrity check failed"))
	}

	return &userdata, nil
}

// This stores a file in the datastore.
//
// The name of the file should NOT be revealed to the datastore!
func (userdata *User) StoreFile(filename string, data []byte) {
	var file File
	var root RootFile

	// generate random things
	uuidFile := uuid.New()
	uuidRoot := uuid.New()
	macKey := userlib.RandomBytes(16)
	fileEncrypt := userlib.RandomBytes(16)
	rootEncrypt := userlib.RandomBytes(16)
	ivData := userlib.RandomBytes(16)
	ivFile := userlib.RandomBytes(16)
	ivRoot = userlib.RandomBytes(16)

	// set fields
	unecrypted := []byte(filename) + data
	encrypted = SymEnc(fileEncrypt, ivData, unecrypted)
	mac := HMACEval(macKey, data)
	file.NameLength = len(filename)
	file.FileData = encrypted
	file.Mac = mac

	root.Files = make([] uuid.UUID, 0)
	root.Files = append(root.Files, uuidFile)

	userdata.RootFiles[filename] = uuidRoot
	userdata.FileKeys[uuidFile.String() + "encrypt"] = fileEncrypt
	userdata.FileKeys[uuidFile.String() + "mac"] = macKey
	userdata.FileKeys[uuidRoot.String()] = rootEncrypt

	// encrypt the files
	fileBytes, err := json.Marshal(file)
	cipherFile := SymEnc(fileEncrypt, ivFile, fileBytes)
	userlib.DatastoreSet(uuidFile, cipherFile)

	rootBytes, err2 := json.Marshal(root)
	cipherRoot := SymEnc(rootEncrypt, ivRoot, rootBytes)
	userlib.DatastoresSet(uuidRoot, cipherRoot)
}

// This adds on to an existing file.
//
// Append should be efficient, you shouldn't rewrite or reencrypt the
// existing file, but only whatever additional information and
// metadata you need.

func (userdata *User) AppendFile(filename string, data []byte) (err error) {
	var file File

	uuidRoot, ok = userdata.RootFiles[filename]
	if !ok {
		return
	}

	uuidFile := uuid.New()
	macKey := userlib.RandomBytes(16)
	fileEncrypt := userlib.RandomBytes(16)
	ivData := userlib.RandomBytes(16)
	ivFile := userlib.RandomBytes(16)

	unecrypted := []byte(filename) + data
	encrypted = SymEnc(fileEncrypt, ivData, unecrypted)
	mac := HMACEval(macKey, data)
	file.NameLength = len(filename)
	file.FileData = encrypted
	file.Mac = mac

	userdata.FileKeys[uuidFile.String() + "encrypt"] = fileEncrypt
	userdata.FileKeys[uuidFile.String() + "mac"] = macKey

	fileBytes, err := json.Marshal(file)
	cipherFile := SymEnc(fileEncrypt, ivFile, fileBytes)
	userlib.DatastoreSet(uuidFile, cipherFile)

	encryptedFiles := userlib.DatastoreGet(uuidRoot)
	rootKey := userdata.FileKeys[uuidRoot.String()]
	rootBytes := userlib.SymDec(rootKey, encryptedFiles)
	json.Unmarshal(rootBytes, root)
	root.Files = append(root.Files, uuidFile)
}

// This loads a file from the Datastore.
//
// It should give an error if the file is corrupted in any way.
func (userdata *User) LoadFile(filename string) (data []byte, err error) {
	return
}

// You may want to define what you actually want to pass as a
// sharingRecord to serialized/deserialize in the data store.
type sharingRecord struct {
}

// This creates a sharing record, which is a key pointing to something
// in the datastore to share with the recipient.

// This enables the recipient to access the encrypted file as well
// for reading/appending.

// Note that neither the recipient NOR the datastore should gain any
// information about what the sender calls the file.  Only the
// recipient can access the sharing record, and only the recipient
// should be able to know the sender.

func (userdata *User) ShareFile(filename string, recipient string) (
	magic_string string, err error) {
	data, err = userdata.LoadFile(filename)
	if err != nil {
		return "", errors.New(strings.ToTitle("No file with this name"))
	}

	return
}

// Note recipient's filename can be different from the sender's filename.
// The recipient should not be able to discover the sender's view on
// what the filename even is!  However, the recipient must ensure that
// it is authentically from the sender.
func (userdata *User) ReceiveFile(filename string, sender string,
	magic_string string) error {
	// check if filename is already under user, if so, throw error
	// register new file under this user
	// but is actually the same file
	return nil
}

// Removes access for all others.
func (userdata *User) RevokeFile(filename string) (err error) {
	data, err = userdata.LoadFile(filename)
	if err != nil {
		return "", errors.New(strings.ToTitle("No file with this name"))
	}
	// delete the file
	userdata.StoreFile(filename, data)
	return
}

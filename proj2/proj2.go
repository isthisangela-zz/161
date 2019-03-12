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
	DecKey userlib.PKEDecKey
	SignKey userlib.DSSignKey
	FatKey []byte // containing MAC key, symmetric encryption key, etc
	RootFiles map[string] uuid.UUID
	FileKeys map[string] []byte
	// You can add other fields here if you want...
	// Note for JSON to marshal/unmarshal, the fields need to
	// be public (start with a capital letter)
}

type File struct {
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
	userlib.KeystoreSet(username + "enc", enckey)
	userlib.KeystoreSet(username + "ver", verkey)

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
	ivRoot := userlib.RandomBytes(16)

	// set fields
	encrypted := userlib.SymEnc(fileEncrypt, ivData, data)
	mac, err := userlib.HMACEval(macKey, data)
	if err != nil {
		return
	}
	file.FileData = encrypted
	file.Mac = mac

	root.Files = make([] uuid.UUID, 0)
	root.Files = append(root.Files, uuidFile)

	userdata.RootFiles[filename] = uuidRoot
	userdata.FileKeys[filename + "encrypt"] = fileEncrypt
	userdata.FileKeys[filename + "mac"] = macKey
	userdata.FileKeys[uuidRoot.String()] = rootEncrypt

	// encrypt the files
	fileBytes, err := json.Marshal(file)
	cipherFile := userlib.SymEnc(fileEncrypt, ivFile, fileBytes)
	userlib.DatastoreSet(uuidFile, cipherFile)

	rootBytes, err2 := json.Marshal(root)
	if err2 != nil {
		return
	}
	cipherRoot := userlib.SymEnc(rootEncrypt, ivRoot, rootBytes)
	userlib.DatastoreSet(uuidRoot, cipherRoot)

	// gotta update the user!
	unbyte := []byte(userdata.Username)
	macbytes, err2 := userlib.HMACEval(userdata.FatKey[:16], unbyte)
	if err2 != nil {
		return
	}
	uuid, _ := uuid.FromBytes(macbytes[:16])

	iv := userlib.RandomBytes(16)
	userjson, err2 := json.Marshal(userdata)
	if err2 != nil {
		return
	}
	cipher := userlib.SymEnc(userdata.FatKey[16:32], iv, userjson)
	userlib.DatastoreSet(uuid, cipher)
}

// This adds on to an existing file.
//
// Append should be efficient, you shouldn't rewrite or reencrypt the
// existing file, but only whatever additional information and
// metadata you need.

func (userdata *User) AppendFile(filename string, data []byte) (err error) {
	var file File

	uuidRoot, ok := userdata.RootFiles[filename]
	if !ok {
		return errors.New(strings.ToTitle("No file with this name"))
	}

	uuidFile := uuid.New()
	ivData := userlib.RandomBytes(16)
	ivFile := userlib.RandomBytes(16)

	macKey := userdata.FileKeys[filename + "mac"]
	fileEncrypt := userdata.FileKeys[filename + "encrypt"]

	encrypted := userlib.SymEnc(fileEncrypt, ivData, data)
	mac, err := userlib.HMACEval(macKey, data)
	if err != nil {
		return err
	}
	file.FileData = encrypted
	file.Mac = mac

	fileBytes, err := json.Marshal(file)
	cipherFile := userlib.SymEnc(fileEncrypt, ivFile, fileBytes)
	userlib.DatastoreSet(uuidFile, cipherFile)

	var root RootFile
	encryptedFiles, ok := userlib.DatastoreGet(uuidRoot)
	if !ok {
		return errors.New(strings.ToTitle("No file with this id"))
	}
	rootKey := userdata.FileKeys[uuidRoot.String()]
	rootBytes := userlib.SymDec(rootKey, encryptedFiles)
	json.Unmarshal(rootBytes, root)
	root.Files = append(root.Files, uuidFile)

	return nil
}

// This loads a file from the Datastore.
//
// It should give an error if the file is corrupted in any way.
func (userdata *User) LoadFile(filename string) (data []byte, err error) {
	uuidRoot, ok := userdata.RootFiles[filename]
	if !ok {
		return nil, errors.New(strings.ToTitle("No file with this name"))
	}
	var root RootFile
	encryptedFiles, ok := userlib.DatastoreGet(uuidRoot)
	if !ok {
		return nil, errors.New(strings.ToTitle("No file with this name"))
	}
	rootKey := userdata.FileKeys[uuidRoot.String()]
	rootBytes := userlib.SymDec(rootKey, encryptedFiles)
	json.Unmarshal(rootBytes, &root)

	macKey := userdata.FileKeys[filename + "mac"]
	fileKey := userdata.FileKeys[filename + "encrypt"]

	for i := 0; i < len(root.Files); i++ {
		var file File
		uuidFile := root.Files[i]
		encrypted, ok := userlib.DatastoreGet(uuidFile)
		if !ok {
			return nil, errors.New(strings.ToTitle("File storage corrupted"))
		}

		fileBytes := userlib.SymDec(fileKey, encrypted)
		json.Unmarshal(fileBytes, &file)

		dataBytes := userlib.SymDec(fileKey, file.FileData)
		newMac, err := userlib.HMACEval(macKey, dataBytes)
		if err != nil {
			return nil, err
		}
		if !userlib.HMACEqual(file.Mac, newMac) {
			return nil, errors.New(strings.ToTitle("Failed integrity test"))
		}

		data = append(data, dataBytes...)
	}

	return data, nil
}

// You may want to define what you actually want to pass as a
// sharingRecord to serialized/deserialize in the data store.
type sharingRecord struct {
	Uuids []byte // or bare minimum of whatever youd need to access and edit the file
	SymKey []byte
	MacKey []byte
}

type recordAndMac struct {
	Record []byte
	Signature []byte
	Hmac []byte
}

// This creates a sharing record, which is a key pointing to something
// in the datastore to share with the recipient.

// This enables the recipient to access the encrypted file as well
// for reading/appending.

// Note that neither the recipient NOR the datastore should gain any
// information about what the sender calls the file.  Only the
// recipient can access the sharing record, and only the recipient
// should be able to know the sender.

func (userdata *User) ShareFile(filename string, recipient string) (magic_string string, err error) {
	// verify file on sender's side
	uuidRoot, ok := userdata.RootFiles[filename]
	if !ok {
		return "", errors.New(strings.ToTitle("No file with this name"))
	}

	// get uuid file
	encrypted, ok := userlib.DatastoreGet(uuidRoot)
	if !ok {
		return "", errors.New(strings.ToTitle("No file with this id"))
	}
	deckey := userdata.FileKeys[uuidRoot]
	uuidFile := userlib.SymDec(deckey, encrypted)

	// CANDACE HELP??? 

	// use it to get keys for encrypting and signing
	symKeyFile := userdata.FileKeys[uuidFile.String() + "encrypt"]
	macKeyFile := userdata.FileKeys[uuidFile.String() + "mac"]

	// initialize sharing record struct
	rec = sharingRecord{Uuids: uuidFile, SymKey: symKeyFile, MacKey: macKeyFile}

	// serialize
	json, err := json.Marshal(rec)
	if err != nil {
		return "", err
	}

	// encryption for confidentiality
	symkey := userlib.RandomBytes(16)
	iv := userlib.RandomBytes(16)
	record := userlib.SymEnc(symkey, iv, json)

	// give digital signature for authenticity
	signkey := userdata.SignKey
	sig, err := userlib.DSSign(signkey, record)
	if err != nil {
		return "", errors.New(strings.ToTitle("Error making signature"))
	}

	// hmac for integrity
	mackey := userlib.RandomBytes(16)
	hmac, err := userlib.HMACEval(mackey, record)
	if err != nil {
		return "", err
	}

	// initialize record and mac struct
	recmac = recordAndMac{Record: record, Signature: sig, Hmac: hmac}

	// serialize
	jsonrecmac, err := json.Marshal(recmac)
	if err != nil {
		return "", err
	}

	// store
	uuidRecord := uuid.New()
	userlib.DatastoreSet(uuidRecord, jsonrecmac)

	// magic string = uuid + symkey + mackey (16, 16, 16)
	magic_slice := append([]byte(uuidRecord.String()), symkey, mackey)

	// encrypt stringyyy
	enckey, ok := userlib.KeystoreGet(recipient + "enc")
	if !ok {
		return "", errors.New(strings.ToTitle("Couldn't find encryption key"))
	}
	pke, err := userlib.PKEEnc(enckey, magic_slice) 

	// HOW DO I GIVE IT INTEGRITY LOOOLLL:)))

	magic_string = string(pke)
	return magic_string, nil
}

// Note recipient's filename can be different from the sender's filename.
// The recipient should not be able to discover the sender's view on
// what the filename even is!  However, the recipient must ensure that
// it is authentically from the sender.
func (userdata *User) ReceiveFile(filename string, sender string, magic_string string) error {
	// check if filename is already under user, if so, throw error
	_, ok := userdata.RootFiles[filename]
	if !ok {
		return errors.New(strings.ToTitle("Recipient already has file with this name"))
	}

	var recmac recordAndMac
	var rec sharingRecord

	// get stuff out of magic_string
	deckey := userdata.DecKey
	magic_slice, err := userlib.PKEDec(deckey, []byte(magic_string))
	if err != nil {
		return err
	}
	uuidRecord := uuid.FromBytes(magic_slice[:16])
	symkey := magic_slice[16:32]
	mackey := magic_slice[32:48]

	// get from datastore and deserialize
	jsonrecmac, ok := userlib.DatastoreGet(uuidRecord)
	if !ok {
		return errors.New(strings.ToTitle("Error fetching from datastore"))
	}
	json.Unmarshal(jsonrecmac, &recmac)
	record := recmac.Record
	sig := recmac.Signature
	hmac := recmac.Hmac

	// verify that it's from the right sender
	verkey, ok := userlib.KeystoreGet(sender + "ver")
	if !ok {
		return errors.New(strings.ToTitle("Could not find sender's public key"))
	}
	err := userlib.DSVerify(verkey, record, sig)
	if err != nil {
		return errors.New(strings.ToTitle("Error verifying signature"))
	}

	// verify hmac
	computehmac, error := HMACEval(mackey, record)
	if err != nil {
		return errors.New(strings.ToTitle("HMACing error"))
	}
	if !HMACEqual(hmac, computehmac) {
		return errors.New(strings.ToTitle("HMACs didn't match up, file tampered with"))
	}

	// decrypt and deserialize
	json := userlib.SymDec(symkey, record)
	json.Unmarshal(json, &rec)
	uuidFile := rec.Uuids
	symKeyFile := rec.SymKey
	macKeyFile := rec.MacKey

	// now we are clear so give the user file access
	// CANDACE HELP
	userdata.StoreFile(filename string, data []byte)
	
	return nil
}

// Removes access for all others.
func (userdata *User) RevokeFile(filename string) (err error) {
	// verify file on sender's side
	uuidRoot, ok := userdata.RootFiles[filename]
	if !ok {
		return errors.New(strings.ToTitle("No file with this name"))
	}

	var root RootFile
	encryptedFiles, ok := userlib.DatastoreGet(uuidRoot)
	if !ok {
		return errors.New(strings.ToTitle("No file with this name"))
	}
	rootKey := userdata.FileKeys[uuidRoot.String()]
	rootBytes := userlib.SymDec(rootKey, encryptedFiles)
	json.Unmarshal(rootBytes, &root)

	macKey := userdata.FileKeys[filename + "mac"]
	fileKey := userdata.FileKeys[filename + "encrypt"]

	var data []byte

	for i := 0; i < len(root.Files); i++ {
		var file File
		uuidFile := root.Files[i]
		encrypted, ok := userlib.DatastoreGet(uuidFile)
		if !ok {
			return errors.New(strings.ToTitle("File storage corrupted"))
		}

		fileBytes := userlib.SymDec(fileKey, encrypted)
		json.Unmarshal(fileBytes, &file)

		dataBytes := userlib.SymDec(fileKey, file.FileData)
		newMac, err := userlib.HMACEval(macKey, dataBytes)
		if err != nil {
			return err
		}
		if !userlib.HMACEqual(file.Mac, newMac) {
			return errors.New(strings.ToTitle("Failed integrity test"))
		}

		data = append(data, dataBytes...)
		userlib.DatastoreDelete(uuidFile)
	}
	userlib.DatastoreDelete(uuidRoots)
	delete(userdata.FileKeys, uuidRoot.String())

	userdata.StoreFile(filename, data)
	return nil
}

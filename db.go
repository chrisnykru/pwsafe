// Package pwsafe provides read/write access to Password Safe V3 databases.
// See https://en.wikipedia.org/wiki/Password_Safe for more information.
// Unsupported fields are preserved so that databases can be
// manipulated without losing information.
//
// Per the V3 specification, HMAC only covers the header and record field data,
// but not the field type or length.
package pwsafe

/*

TODO: consider forcing titles to be unique?


TODO: don't fail on error for DB Open, ignore non-fatal errors and provide them as feedback from operation...
part of a DB is better than nothing, depending on what client wants.

TODO: Consider allowing caller to override RNG for Encode()?

*/

import (
	"bytes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"golang.org/x/crypto/twofish"
	"hash"
	"io/ioutil"
	"log"
	"math"
	"os"
	"time"
	"unicode/utf8"
)

const Version = "0.0.1"

const (
	eofMarker = "PWS3-EOFPWS3-EOF"
)

var (
	ErrInvalidDatabase = errors.New("invalid database")
)

type RawField struct {
	Kind uint8
	Data []byte
}

// TODO: aliases (3.3.3), shortcuts (3.3.4)
type Record struct {
	UUID           [16]byte
	Group          string
	Title          string
	Username       string
	Email          string
	Notes          string
	Pass           string
	CreationTime   time.Time
	PassModTime    time.Time
	LastAccessTime time.Time
	LastModTime    time.Time
	URL            string
	// Password expiry time, 'protected' status, autotype, password history,
	// password policy, double-click action, allowed symbols for password
	// generation, shift double-click action
	UnimplementedFields []RawField
}

func (r *Record) deepCopy() Record {
	r2 := Record{
		UUID:                r.UUID,
		Group:               r.Group,
		Title:               r.Title,
		Username:            r.Username,
		Notes:               r.Notes,
		Pass:                r.Pass,
		CreationTime:        r.CreationTime,
		PassModTime:         r.PassModTime,
		LastAccessTime:      r.LastAccessTime,
		LastModTime:         r.LastModTime,
		URL:                 r.URL,
		UnimplementedFields: append([]RawField{}, r.UnimplementedFields...),
	}
	return r2
}

type recordBuilder struct {
	*Record
	uuidSet bool
}

func newRecordBuilder() *recordBuilder {
	return &recordBuilder{new(Record), false}
}

// TODO: when a record field is absent OR zero-length, its default value is used..!
func (rb *recordBuilder) BuildAndReset() (*Record, error) {
	if !rb.uuidSet {
		return nil, errors.New("missing required field")
	}
	if rb.Title == "" {
		return nil, errors.New("missing required field")
	}
	if rb.Pass == "" {
		return nil, errors.New("missing required field")
	}
	r := rb.Record
	rb.Record = new(Record)
	rb.uuidSet = false
	return r, nil
}

func (rb *recordBuilder) SetUUID(uuid []byte) {
	copy(rb.UUID[:], uuid)
	rb.uuidSet = true
}

func parseV3Time(fieldData []byte) (time.Time, error) {
	switch len(fieldData) {
	case 4:
		var ts uint32
		err := binary.Read(bytes.NewReader(fieldData), binary.LittleEndian, &ts)
		if err != nil {
			return time.Time{}, err
		}
		return time.Unix(int64(ts), 0), nil
	case 8:
		// DecodeString() returns []byte of length input/2
		b, err := hex.DecodeString(string(fieldData))
		if err != nil {
			return time.Time{}, err
		}
		return parseV3Time(b)

	default:
		return time.Time{}, errors.New("bad timestamp field length")
	}
}

type Header struct {
	Version           uint16
	UUID              [16]byte
	Name              string
	Description       string
	LastSaveTimestamp time.Time
	LastSaveByWhat    string
	LastSaveByUser    string
	LastSaveOnHost    string
	// Non-default preferences, tree display status, recently used entries,
	// empty groups
	UnimplementedFields []RawField
}

func (h *Header) deepCopy() Header {
	h2 := Header{
		Version:             h.Version,
		UUID:                h.UUID,
		Name:                h.Name,
		Description:         h.Description,
		LastSaveTimestamp:   h.LastSaveTimestamp,
		LastSaveByWhat:      h.LastSaveByWhat,
		LastSaveByUser:      h.LastSaveByUser,
		LastSaveOnHost:      h.LastSaveOnHost,
		UnimplementedFields: append([]RawField{}, h.UnimplementedFields...),
	}
	return h2
}

type PWSafeV3 struct {
	isValid       bool
	salt          [32]byte
	iter          uint32
	encryptionKey [32]byte
	hmacKey       [32]byte
	cbcIV         [16]byte
	stretchedKey  [sha256.Size]byte
	hdr           Header
	records       []*Record
	hmac          [32]byte
}

func (db *PWSafeV3) SetUUID(uuid [16]byte) {
	db.hdr.UUID = uuid
}

func checkString(s string) error {
	if int64(len(s)) > math.MaxUint32 {
		return errors.New("string length overflows 32 bits")
	}
	if !utf8.ValidString(s) {
		return errors.New("string is not valid UTF8")
	}
	return nil
}

func checkFieldData(x []byte) error {
	if int64(len(x)) > math.MaxUint32 {
		return errors.New("field length overflows 32 bits")
	}
	return nil
}

// Returns error if s is not valid UTF8
func (db *PWSafeV3) SetName(s string) error {
	if err := checkString(s); err != nil {
		return err
	}
	db.hdr.Name = s
	return nil
}

// Returns error if s is not valid UTF8
func (db *PWSafeV3) SetDescription(s string) error {
	if err := checkString(s); err != nil {
		return err
	}
	db.hdr.Description = s
	return nil
}

func (db *PWSafeV3) SetLastSaveTimestamp(t time.Time) {
	db.hdr.LastSaveTimestamp = t
}

// Returns error if what, user, or host is not valid UTF8
func (db *PWSafeV3) SetLastSaveBy(what, user, host string) error {
	if err := checkString(what); err != nil {
		return err
	}
	if err := checkString(user); err != nil {
		return err
	}
	if err := checkString(host); err != nil {
		return err
	}
	db.hdr.LastSaveByWhat = what
	db.hdr.LastSaveByUser = user
	db.hdr.LastSaveOnHost = host
	return nil
}

// Returns error if any field data length exceeds 32 bits
func (db *PWSafeV3) SetUnimplementedHeaderFields(fields []RawField) error {
	for _, f := range fields {
		if err := checkFieldData(f.Data); err != nil {
			return err
		}
	}
	db.hdr.UnimplementedFields = append([]RawField{}, fields...)
	return nil
}

func (db *PWSafeV3) Iterations() uint32 {
	return db.iter
}

func encodeInt(data interface{}) []byte {
	var b bytes.Buffer
	err := binary.Write(&b, binary.LittleEndian, data)
	if err != nil {
		panic(err)
	}
	return b.Bytes()
}

func encodeField(b *bytes.Buffer, ftype uint8, fdata []byte, mac hash.Hash) {
	if len(fdata) > math.MaxUint32 {
		panic("len(fdata) > math.MaxUint32")
	}
	err := binary.Write(b, binary.LittleEndian, uint32(len(fdata)))
	if err != nil {
		panic(err)
	}
	b.WriteByte(ftype)
	b.Write(fdata)
	mac.Write(fdata)

	// pad to twofish block size
	// TODO CRYPTO: What kind of padding should we use?!
	n := int64(5) + int64(len(fdata))
	bmod := n % twofish.BlockSize
	if bmod != 0 {
		padding := twofish.BlockSize - bmod
		b.Write(bytes.Repeat([]byte{byte(padding)}, int(padding)))
	}
}

func encodeTimeField(b *bytes.Buffer, ftype uint8, ts time.Time, mac hash.Hash) {
	x := ts.Unix()
	if x > math.MaxUint32 {
		panic("ts > math.MaxUint32")
	}
	encodeField(b, ftype, encodeInt(uint32(x)), mac)
}

func encodeRecord(b *bytes.Buffer, r *Record, mac hash.Hash) {
	var zeroTime time.Time
	encodeField(b, 0x01, r.UUID[:], mac) // mandatory
	if len(r.Group) > 0 {
		encodeField(b, 0x02, []byte(r.Group), mac)
	}
	encodeField(b, 0x03, []byte(r.Title), mac) // mandatory
	if len(r.Username) > 0 {
		encodeField(b, 0x04, []byte(r.Username), mac)
	}
	if len(r.Notes) > 0 {
		encodeField(b, 0x05, []byte(r.Notes), mac)
	}
	encodeField(b, 0x06, []byte(r.Pass), mac) // mandatory
	if r.CreationTime != zeroTime {
		encodeTimeField(b, 0x07, r.CreationTime, mac)
	}
	if r.PassModTime != zeroTime {
		encodeTimeField(b, 0x08, r.PassModTime, mac)
	}
	if r.LastAccessTime != zeroTime {
		encodeTimeField(b, 0x09, r.LastAccessTime, mac)
	}
	if r.LastModTime != zeroTime {
		encodeTimeField(b, 0x0c, r.LastModTime, mac)
	}
	if len(r.URL) > 0 {
		encodeField(b, 0x0d, []byte(r.URL), mac)
	}
	if len(r.Email) > 0 {
		encodeField(b, 0x14, []byte(r.Email), mac)
	}
	for _, f := range r.UnimplementedFields {
		encodeField(b, f.Kind, f.Data, mac)
	}
	encodeField(b, 0xff, []byte{}, mac) // mandatory
}

// Useful for saving db to file
func (db *PWSafeV3) Encode(pass []byte, iter uint32) ([]byte, error) {
	if !db.isValid {
		return nil, ErrInvalidDatabase
	}

	var b bytes.Buffer
	b.WriteString("PWS3") // Tag

	/*
		note: Original passwordsafe software SHA256's the randomly generated 32-byte
		value before writing it out as the salt, fearing that an attacker could gain
		some sort of advantage with direct access to the generated randomness.
		I don't know enough to agree or disagree with this approach, so I'm
		just going to keep it simple and trust the RNG.
	*/
	salt := make([]byte, 32)
	_, err := rand.Read(salt)
	if err != nil {
		panic(err)
	}
	b.Write(salt)
	b.Write(encodeInt(iter))

	stretchedKey := calculateStretchedKey(pass, salt, iter, 0, nil)
	H_of_Pprime := sha256.Sum256(stretchedKey[:])
	b.Write(H_of_Pprime[:])

	// B1, B2
	c, err := twofish.NewCipher(stretchedKey[:])
	if err != nil {
		panic(err)
	}
	encryptionKey := make([]byte, 32)
	_, err = rand.Read(encryptionKey)
	if err != nil {
		panic(err)
	}
	bkey := make([]byte, 32)
	c.Encrypt(bkey[:16], encryptionKey[:16])
	c.Encrypt(bkey[16:32], encryptionKey[16:32])
	b.Write(bkey)

	// B3, B4; note: K and L must not be "related"
	hmacKey := make([]byte, 32)
	_, err = rand.Read(hmacKey)
	if err != nil {
		panic(err)
	}
	c.Encrypt(bkey[:16], hmacKey[:16])
	c.Encrypt(bkey[16:32], hmacKey[16:32])
	b.Write(bkey)

	// Don't re-use the old CBC IV
	// question: Can an attacker w/ ability to observe ciphertext over time (e.g., dropbox)
	// attack the PWSafeV3 if the CBCIV is ever re-used?  In other words, is the CBCIV
	// like a nonce?  If so, should we keep track of it (e.g., some proprietary field), so as to
	// never repeat it?
	cbcIV := make([]byte, 16)
	_, err = rand.Read(cbcIV)
	if err != nil {
		panic(err)
	}
	b.Write(cbcIV)

	// Write header to plaintext buffer
	var bplain bytes.Buffer
	mac := hmac.New(sha256.New, hmacKey)
	encodeField(&bplain, 0x00, encodeInt(uint16(0x0300)), mac) // Version

	encodeField(&bplain, 0x01, db.hdr.UUID[:], mac)
	encodeField(&bplain, 0x09, []byte(db.hdr.Name), mac)
	encodeField(&bplain, 0x0a, []byte(db.hdr.Description), mac)
	encodeTimeField(&bplain, 0x04, db.hdr.LastSaveTimestamp, mac)
	encodeField(&bplain, 0x06, []byte(db.hdr.LastSaveByWhat), mac)
	encodeField(&bplain, 0x07, []byte(db.hdr.LastSaveByUser), mac)
	encodeField(&bplain, 0x08, []byte(db.hdr.LastSaveOnHost), mac)

	for _, f := range db.hdr.UnimplementedFields {
		encodeField(&bplain, f.Kind, f.Data, mac)
	}
	encodeField(&bplain, 0xff, []byte{}, mac) // end of header

	for _, r := range db.records {
		encodeRecord(&bplain, r, mac)
	}

	if bplain.Len()%twofish.BlockSize != 0 {
		panic("Data size is not a multiple of the cipher block size")
	}

	// Encrypt header and records and write to main buffer
	c, err = twofish.NewCipher(encryptionKey)
	if err != nil {
		panic(err)
	}
	blockMode := cipher.NewCBCEncrypter(c, cbcIV)
	ciphertext := make([]byte, bplain.Len())
	blockMode.CryptBlocks(ciphertext, bplain.Bytes())
	b.Write(ciphertext)

	b.WriteString(eofMarker)

	hmac := mac.Sum(nil)
	if len(hmac) != 32 {
		panic("len(hmac) != 32")
	}
	b.Write(hmac)
	return b.Bytes(), nil
}

// Returns SHA256 Sum
func calculateStretchedKey(pass []byte, salt []byte, iter uint32, progressInterval time.Duration, progressFunc func(float64)) [sha256.Size]byte {
	sk := sha256.Sum256(append(pass, salt...))

	var ticks <-chan time.Time
	if progressInterval > 0 && progressFunc != nil {
		t := time.NewTicker(progressInterval)
		defer t.Stop()
		ticks = t.C
	}

	for i := uint32(0); i < iter; {
		select {
		case <-ticks:
			percentDone := float64(i) * 100 / float64(iter)
			progressFunc(percentDone)
		default:
			sk = sha256.Sum256(sk[:])
			i++
		}
	}
	return sk
}

func (db *PWSafeV3) ListRecords() []Record {
	list := make([]Record, 0, len(db.records))
	for _, r := range db.records {
		list = append(list, r.deepCopy())
	}
	return list
}

func (db *PWSafeV3) Header() Header {
	return db.hdr.deepCopy()
}

// Returns number of bytes read, field type, field data, error
func decodeField(b []byte) (int64, uint8, []byte, error) {
	if len(b) < 4 /*field len*/ +1 /*field type*/ {
		return 0, 0, nil, errors.New("truncated field")
	}
	var fieldLen uint32
	err := binary.Read(bytes.NewReader(b[0:4]), binary.LittleEndian, &fieldLen)
	if err != nil {
		return 0, 0, nil, err
	}
	fieldType := uint8(b[4])
	b = b[5:]
	if int64(len(b)) < int64(fieldLen) {
		return 0, 0, nil, errors.New("truncated field")
	}

	fieldData := make([]byte, int64(fieldLen))
	copy(fieldData, b[:int64(fieldLen)])

	n := int64(5) + int64(fieldLen)

	// padding
	bmod := n % twofish.BlockSize
	if bmod != 0 {
		n += twofish.BlockSize - bmod
	}
	return n, fieldType, fieldData, nil
}

// Returns number of bytes read and optional error
func (db *PWSafeV3) decodeHeader(b []byte, mac hash.Hash) (int64, error) {
	n := int64(0)
	fieldCount := 0
loop:
	for {
		fieldCount++

		n2, fieldType, fieldData, err := decodeField(b[n:])
		if err != nil {
			return n, err
		}
		n += n2

		// Update hmac; spec forces us to only hmac the fieldData, leaving type and length unprotected!
		mac.Write(fieldData)

		if (fieldCount == 1 && fieldType != 0x00) || (fieldType == 0x00 && fieldCount != 1) {
			return n, errors.New("db version field must come first")
		}

		switch fieldType {
		case 0x00: // version
			if len(fieldData) != 2 {
				return n, errors.New("bad field length for type")
			}
			err = binary.Read(bytes.NewReader(fieldData), binary.LittleEndian, &db.hdr.Version)
			if err != nil {
				return n, err
			}
			if db.hdr.Version&0xff00 != 0x0300 {
				return n, errors.New("bad version: " + fmt.Sprintf("%#04x", db.hdr.Version))
			}
		case 0x01: // UUID
			if len(fieldData) != 16 {
				return n, errors.New("bad field length for type")
			}
			copy(db.hdr.UUID[:], fieldData)

		case 0x02: // non-default preferences
			db.hdr.UnimplementedFields = append(db.hdr.UnimplementedFields, RawField{fieldType, fieldData})

		case 0x03: // tree display status
			db.hdr.UnimplementedFields = append(db.hdr.UnimplementedFields, RawField{fieldType, fieldData})

		case 0x04: // last save timestamp
			ts, err := parseV3Time(fieldData)
			if err != nil {
				return n, err
			}
			db.hdr.LastSaveTimestamp = ts

		case 0x06: // last save by what
			s := string(fieldData)
			if err := checkString(s); err != nil {
				return n, err
			}
			db.hdr.LastSaveByWhat = s

		case 0x07: // last save by user
			s := string(fieldData)
			if err := checkString(s); err != nil {
				return n, err
			}
			db.hdr.LastSaveByUser = s

		case 0x08: // last save on host
			s := string(fieldData)
			if err := checkString(s); err != nil {
				return n, err
			}
			db.hdr.LastSaveOnHost = s

		case 0x09: // db name
			s := string(fieldData)
			if err := checkString(s); err != nil {
				return n, err
			}
			db.hdr.Name = s

		case 0x0a: // db description
			s := string(fieldData)
			if err := checkString(s); err != nil {
				return n, err
			}
			db.hdr.Description = s

		case 0x0f: // recently used entries
			db.hdr.UnimplementedFields = append(db.hdr.UnimplementedFields, RawField{fieldType, fieldData})

		case 0x11: // empty groups
			db.hdr.UnimplementedFields = append(db.hdr.UnimplementedFields, RawField{fieldType, fieldData})

		case 0xff: // end
			if len(fieldData) != 0 {
				return n, errors.New("bad field length for type")
			}
			// Only non-error way out of loop is this break; guarantees last field is 0xff
			break loop

		default:
			log.Printf("Unknown header fieldType = %#x fieldLen = %v fieldData = %v\n", fieldType, len(fieldData), fieldData)
			db.hdr.UnimplementedFields = append(db.hdr.UnimplementedFields, RawField{fieldType, fieldData})
		}
	}
	return n, nil
}

// Returns number of bytes read and optional error
func (db *PWSafeV3) decodeRecords(b []byte, mac hash.Hash) (int64, error) {
	n := int64(0)
	rb := newRecordBuilder()
	for {
		// no more records?
		if n == int64(len(b)) {
			break
		}

		n2, fieldType, fieldData, err := decodeField(b[n:])
		if err != nil {
			return n, err
		}
		n += n2

		// Update hmac; spec forces us to only hmac the fieldData, leaving type and length unprotected!
		mac.Write(fieldData)

		switch fieldType {
		case 0x01: // uuid
			if len(fieldData) != 16 {
				return n, errors.New("bad field length for type")
			}
			rb.SetUUID(fieldData)

		case 0x02: // group
			s := string(fieldData)
			if err := checkString(s); err != nil {
				return n, err
			}
			rb.Group = s

		case 0x03: // title
			s := string(fieldData)
			if err := checkString(s); err != nil {
				return n, err
			}
			rb.Title = s

		case 0x04: // username
			s := string(fieldData)
			if err := checkString(s); err != nil {
				return n, err
			}
			rb.Username = s

		case 0x05: // notes
			s := string(fieldData)
			if err := checkString(s); err != nil {
				return n, err
			}
			rb.Notes = s

		case 0x06: // password
			s := string(fieldData)
			if err := checkString(s); err != nil {
				return n, err
			}
			rb.Pass = s

		case 0x07: // creation time
			ts, err := parseV3Time(fieldData)
			if err != nil {
				return n, err
			}
			rb.CreationTime = ts

		case 0x08: // password modification time
			ts, err := parseV3Time(fieldData)
			if err != nil {
				return n, err
			}
			rb.PassModTime = ts

		case 0x09: // last access time
			ts, err := parseV3Time(fieldData)
			if err != nil {
				return n, err
			}
			rb.LastAccessTime = ts

		case 0x0a: // password expiry time
			rb.UnimplementedFields = append(rb.UnimplementedFields, RawField{fieldType, fieldData})

		case 0x0c: // last mod time
			ts, err := parseV3Time(fieldData)
			if err != nil {
				return n, err
			}
			rb.LastModTime = ts

		case 0x0d: // URL
			rb.URL = string(fieldData)

		case 0x0e: // Autotype
			rb.UnimplementedFields = append(rb.UnimplementedFields, RawField{fieldType, fieldData})

		case 0x0f: // password history
			rb.UnimplementedFields = append(rb.UnimplementedFields, RawField{fieldType, fieldData})

		case 0x10: // password policy
			rb.UnimplementedFields = append(rb.UnimplementedFields, RawField{fieldType, fieldData})

		case 0x12: // "run" command
			rb.UnimplementedFields = append(rb.UnimplementedFields, RawField{fieldType, fieldData})

		case 0x13: // double-click action
			rb.UnimplementedFields = append(rb.UnimplementedFields, RawField{fieldType, fieldData})

		case 0x14: // email address
			s := string(fieldData)
			if err := checkString(s); err != nil {
				return n, err
			}
			rb.Email = s

		case 0x15: // protected entry
			rb.UnimplementedFields = append(rb.UnimplementedFields, RawField{fieldType, fieldData})

		case 0x16: // allowed symbols for password generation
			rb.UnimplementedFields = append(rb.UnimplementedFields, RawField{fieldType, fieldData})

		case 0x17: // shift double-click action
			rb.UnimplementedFields = append(rb.UnimplementedFields, RawField{fieldType, fieldData})

		case 0xff: // end of entry
			r, err := rb.BuildAndReset()
			if err != nil {
				return n, err
			}
			db.records = append(db.records, r)

		default:
			log.Printf("Unknown record fieldType = %#x fieldLen = %v fieldData = %v\n", fieldType, len(fieldData), fieldData)
			rb.UnimplementedFields = append(rb.UnimplementedFields, RawField{fieldType, fieldData})
		}
	}

	return n, nil
}

// Databases with high iterations can take a long time to decode.
// If progressInterval is > 0 and progressFunc != nil, progressFunc will be invoked
// with a value [0,100] every 'interval' duration.
func Decode(b []byte, pass []byte, progressInterval time.Duration, progressFunc func(float64)) (*PWSafeV3, error) {
	db := PWSafeV3{}
	minBytes := 4 /*tag*/ + 32 /*salt*/ + 4 /*iterations*/ + 32 /*H(P')*/ + 16*4 /*B1,B2,B3,B4*/ + 16 /*CBCIV*/ + 16 /*EOF*/ + 32 /*HMAC*/
	if len(b) < minBytes {
		return nil, errors.New("DB is too small")
	}
	// Tag
	if string(b[:4]) != "PWS3" {
		return nil, errors.New("Invalid PWSafeV3 file")
	}
	b = b[4:]
	// Salt
	copy(db.salt[:], b[:32])
	b = b[32:]
	// Iterations
	err := binary.Read(bytes.NewReader(b[:4]), binary.LittleEndian, &db.iter)
	if err != nil {
		return nil, errors.New("Invalid iterations")
	}
	b = b[4:]
	// Set stretched key
	db.stretchedKey = calculateStretchedKey(pass, db.salt[:], db.iter, progressInterval, progressFunc)

	// Verify H(P')
	expected_H_of_Pprime := sha256.Sum256(db.stretchedKey[:])
	if bytes.Compare(expected_H_of_Pprime[:], b[:32]) != 0 {
		return nil, errors.New("Invalid pass")
	}
	b = b[32:]

	// Decrypt B1, B2
	c, err := twofish.NewCipher(db.stretchedKey[:])
	if err != nil {
		return nil, err
	}
	Bkey := make([]byte, 32)
	c.Decrypt(Bkey[:16], b[:16])
	c.Decrypt(Bkey[16:32], b[16:32])
	copy(db.encryptionKey[:], Bkey)
	b = b[32:]

	// Decrypt B3, B4
	c.Decrypt(Bkey[:16], b[:16])
	c.Decrypt(Bkey[16:32], b[16:32])
	copy(db.hmacKey[:], Bkey)
	b = b[32:]

	// Init Vector
	copy(db.cbcIV[:], b[:16])
	b = b[16:]

	// Decrypt header and records
	c, err = twofish.NewCipher(db.encryptionKey[:])
	if err != nil {
		return nil, err
	}
	blockMode := cipher.NewCBCDecrypter(c, db.cbcIV[:])
	hdrAndRecordsLength := int64(len(b)) - 16 /* EOF */ - 32 /* HMAC */
	if hdrAndRecordsLength%twofish.BlockSize != 0 {
		return nil, errors.New("Data size is not a multiple of the cipher block size")
	}

	plaintext := make([]byte, hdrAndRecordsLength)
	blockMode.CryptBlocks(plaintext, b[:hdrAndRecordsLength])

	// Init hmac
	mac := hmac.New(sha256.New, db.hmacKey[:])
	n, err := db.decodeHeader(plaintext, mac)
	if err != nil {
		return nil, err
	}
	n2, err := db.decodeRecords(plaintext[n:], mac)
	if err != nil {
		return nil, err
	}
	if n+n2 != hdrAndRecordsLength {
		return nil, errors.New("internal offset error")
	}
	b = b[hdrAndRecordsLength:]
	// Get EOF record
	if string(b[:16]) != eofMarker {
		return nil, errors.New("Bad EOF marker")
	}
	b = b[16:]
	// Get and verify HMAC
	copy(db.hmac[:], b[:32])
	b = b[32:]
	expectedMAC := mac.Sum(nil)
	if !hmac.Equal(db.hmac[:], expectedMAC) {
		return nil, errors.New("HMAC mismatch!")
	}
	// Sanity check
	if len(b) != 0 {
		panic("internal offset error")
	}
	db.isValid = true
	return &db, nil
}

// Databases with high iterations can take a long time to decode.
// If progressInterval is > 0 and progressFunc != nil, progressFunc will be invoked
// with a value [0,100] every 'interval' duration.
func ReadFileWithPeriodicProgress(path string, pass []byte, progressInterval time.Duration, progressFunc func(f float64)) (*PWSafeV3, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := ioutil.ReadAll(f)
	if err != nil {
		return nil, err
	}
	db, err := Decode(b, pass, progressInterval, progressFunc)
	if err != nil {
		return nil, err
	}
	return db, nil
}

func ReadFile(path string, pass []byte) (*PWSafeV3, error) {
	return ReadFileWithPeriodicProgress(path, pass, 0, nil)
}

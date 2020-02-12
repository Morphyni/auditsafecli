// Copyright (c) 2015-2017 TIBCO Software Inc.
// All Rights Reserved

package utils

import (
	"fmt"
	"os"
	"strings"

	"github.com/urfave/cli"
)

var quoteEscaper = strings.NewReplacer("\\", "\\\\", `"`, "\\\"")

// EscapeQuotes escapes the quotes for the given string
func EscapeQuotes(s string) string {
	return quoteEscaper.Replace(s)
}

// // find substring within another string
// func FindSubstring(s string, pos int, length int) string {
// 	runes := []rune(s)
// 	l := pos + length
// 	if l > len(runes) {
// 		l = len(runes)
// 	}
// 	return string(runes[pos:l])
// }

// IncorrectUsageError is a custom error representing an incorrect command usage
type IncorrectUsageError struct {
	Context *cli.Context
	Msg     string
}

// Error implements the interface method error.Message()
func (e *IncorrectUsageError) Error() string {
	return e.Msg
}

// CheckError is a generic error checker. If the supplied error nil, this is a no-op. If
// the error is an IncorrectUsageError, it displays the help for the command, else it displays
// the error and exit the current application
func CheckError(err error) {
	if err != nil {
		switch e := err.(type) {
		case *IncorrectUsageError:
			fmt.Printf("Incorrect Usage: %s\n\n", e)
			cli.ShowSubcommandHelp(e.Context)
		default:
			fmt.Printf("Error: %v\n", e)
		}
		os.Exit(1)
	}
}

/**
// GetSandboxType returns 'N/A' if the original value is empty , otherwise return original value directly for display.
func GetSandboxType(original string) string {
	if original == "" {
		return "N/A"
	}
	return original
}

// GetRealDisplayValue returns 'N/A' if the original value is empty , otherwise return original value directly for display.
func GetRealDisplayValue(original string) string {
	if original == "" {
		return "N/A"
	}
	return original
}

// GetErrorResponse reads json string from reader and returns ErrorResponse
func GetErrorResponse(reader io.Reader) (*types.ErrorResponse, error) {
	bytes, err := ioutil.ReadAll(reader)
	log.Debugf("Error response: %s", string(bytes))
	if err != nil {
		return nil, err
	}
	errorResponse := &types.ErrorResponse{}
	err = json.Unmarshal(bytes, errorResponse)
	if err != nil {
		return nil, err
	}
	return errorResponse, nil
}

// IsJsonUnmarshalError returns true if error is caused by json unmarshalling
func IsJsonUnmarshalError(err error) bool {
	if _, ok := err.(*json.SyntaxError); ok {
		return true
	}
	if _, ok := err.(*json.UnmarshalTypeError); ok {
		return true
	}
	return false
}

// ReadJsonFileIntoString reads a .json file into string
func ReadJsonFileIntoString(relativePathToJsonFile string) (string, error) {
	readBytes, err := ioutil.ReadFile(relativePathToJsonFile)
	if err != nil {
		return "", err
	}
	return string(readBytes[:]), nil
}

// LoadProfile loads user Profile
func LoadProfile() (*settings.Profile, error) {
	profile, err := settings.NewProfile()
	if err != nil {
		return nil, err
	}
	err = profile.Read()
	if err != nil {
		return nil, err
	}
	return profile, nil
}

// LoadSession loads user Session
func LoadSession(unobfuscate bool) (*settings.Session, error) {
	session, err := settings.NewSession()
	if err != nil {
		return nil, err
	}
	err = session.Read(unobfuscate)
	if err != nil {
		return nil, err
	}
	return session, nil
}

// LoadToken loads user TA AccessToken
func LoadToken(unobfuscate bool) (*settings.Token, error) {
	token, err := settings.NewToken()
	if err != nil {
		return nil, err
	}
	err = token.Read(unobfuscate)
	if err != nil {
		return nil, err
	}
	return token, nil
}

// LoadSettings loads user's all token/profile/session from ~/.tibcli
func LoadSettings() (*settings.Profile, *settings.Session, *settings.Token, error) {
	profile, err := LoadProfile()
	if err != nil {
		return nil, nil, nil, err
	}
	session, err := LoadSession(consts.OBFUSCATE_COOKIE_VALUE)
	if err != nil {
		return nil, nil, nil, err
	}
	token, err := LoadToken(consts.OBFUSCATE_COOKIE_VALUE)
	if err != nil {
		return nil, nil, nil, err
	}
	return profile, session, token, err
}

// GetEnvParam get env param value
func GetEnvParam(name string) string {
	value := os.Getenv(name)
	if value != "" {
		log.Debugf("Env param '%s' is found, it has value: %s", name, value)
	} else {
		log.Debugf("Env param '%s' is not found", name)
	}
	return value
}

// GetDesiredInstanceCount calculates the desiredInstanceCount
func GetDesiredInstanceCount(defaultDesiredInstanceCount uint, instancesRequested string) (uint, error) {
	desiredInstanceCount := defaultDesiredInstanceCount
	if instancesRequested != "" {
		// push with argument, use argument number
		di, err := strconv.ParseUint(instancesRequested, 10, 64)
		if err != nil {
			return 0, errors.New(fmt.Sprintf("First argument '%s' must be a valid integer number.", instancesRequested))
		}
		desiredInstanceCount = uint(di)
	}

	return desiredInstanceCount, nil
}

func GetRealCommandNameByScaleMode(scaleMode uint8) string {
	switch scaleMode {
	case consts.APP_SCALE_UP:
		return "scaleup"
	case consts.APP_SCALE_DOWN:
		return "scaledown"
	case consts.APP_SCALE_TO:
		return "scaleto"
	}
	// Should never reach here
	return ""
}

// GetCookieJar creates cookieJar instance and equip it with cookies read from session file
func GetCookieJar(serverUrl *url.URL) (*cookiejar.Jar, error) {

	if serverUrl == nil {
		domainUrl, err := GetDomainURL()
		if err != nil {
			return nil, err
		}
		parsedURL, err := url.Parse(domainUrl)
		if err != nil {
			return nil, err
		}
		serverUrl = parsedURL
	}

	session, err := LoadSession(consts.OBFUSCATE_COOKIE_VALUE)
	if err != nil {
		return nil, err
	}
	if session.Cookies == nil || len(session.Cookies) == 0 {
		return nil, errors.New("session has empty cookies")
	}
	cookieJar, err := cookiejar.New(nil)
	if err != nil {
		return nil, err
	}

	cookieJar.SetCookies(serverUrl, session.Cookies)
	return cookieJar, nil
}

// captureStringReader is a wrapper to io.Reader that captures the bytes
// that are read while being read.
type captureReader struct {
	io.Reader
	allBytes []byte // all bytes that were transferred
}

// Read 'overrides' the underlying io.Reader's Read method.
// This is the one that will be called by io.Copy(). We simply
// use it to capture the bytes that were read.
func (cr *captureReader) Read(p []byte) (int, error) {
	// call internal reader and save the bytes that were successfully read
	n, err := cr.Reader.Read(p)
	if err == nil {
		cr.allBytes = append(cr.allBytes, p[:n]...)
	}
	return n, err
}

// ParseManifest tries to find a manifest in the directory and parses it or returns an error if something goes wrong
func ParseManifest(appLocation string) (*types.Manifest, error) {
	manifestLocation := path.Join(appLocation, consts.MANIFEST_NAME)
	log.Debugf("Parsing Manifest:  '%s'", manifestLocation)
	f, err := ioutil.ReadFile(manifestLocation)
	if err != nil {
		log.Debugf("Error reading file '%s'", manifestLocation)

		if strings.Contains(err.Error(), "no such file or directory") {
			err = errors.New("Run tibcli push from the directory where you have the manifest.json and artifacts.")
		}

		return nil, err
	}
	var manifest *types.Manifest
	// Validate that is a valid json
	err = json.Unmarshal(f, &manifest)
	if err != nil {
		log.Debugf("Error parsing manifest file '%s'", manifestLocation)
		return nil, fmt.Errorf("Invalid manifest file '%s': %s", manifestLocation, err)
	}

	if manifest.Name == "" {
		errMsg := "Manifest validation failed: Name is a required field in Manifest file."
		log.Debugf(errMsg)
		return nil, fmt.Errorf(errMsg)
	}

	matched, err := DoRegExpMatchValidate(consts.REGEXP_PATTERN_FOR_APP_NAME, manifest.Name)
	if err != nil {
		log.Debugf("Error validating app name in manifest file '%s'", manifestLocation)
		return nil, fmt.Errorf("Invalid app name in manifest file '%s': %s", manifestLocation, err)
	}

	if !matched {
		errMsg := "Manifest name attribute may only contain a-z lowercase,  A-Z uppercase characters,  0-9 digits and _.-"
		log.Debugf(errMsg)
		return nil, fmt.Errorf(errMsg)
	}

	return manifest, nil
}

func DoRegExpMatchValidate(pattern, strToValidate string) (bool, error) {
	return regexp.MatchString(pattern, strToValidate)
}

// WriteArtifactFile is private function which writes files on multipart writer
func WriteArtifactFile(artifact string, writer *multipart.Writer) error {

	log.Debugf("Adding file: %s", artifact)
	filename := filepath.Base(artifact)

	part, err := writer.CreateFormFile(filename, filename)
	if err != nil {
		msg := fmt.Sprintf("Create form-data header for file '%s' failed with error '%s' ", artifact, err.Error())
		return errors.New(msg)
	}

	artifactFile, err := os.Open(artifact)
	if err != nil {
		msg := fmt.Sprintf("Open artifact file '%+v' failed with error '%+v'", artifactFile, err.Error())
		return errors.New(msg)
	}
	defer artifactFile.Close()

	// only for manifest file: capture the file for debug logging.
	isManifestFile := (filename == consts.MANIFEST_NAME)
	if isManifestFile {
		capturedArtifactFile := &captureReader{Reader: artifactFile, allBytes: []byte{}}
		if _, err = io.Copy(part, capturedArtifactFile); err == nil {
			log.Debugf("ManifestContent: %s", string(capturedArtifactFile.allBytes))
		}
	} else {
		_, err = io.Copy(part, artifactFile)
	}
	if err != nil {
		msg := fmt.Sprintf("Copy file '%+v' failed with error '%+v'", artifactFile, err.Error())
		return errors.New(msg)
	}

	log.Debugf("Added file: %s", artifact)
	return nil
}

// shutdownHandlers is a map of registered handlers functions that are executed in no particular orders when
// os interrupt signal like ctrl+c is received before doing an os.Exit  for short "last rites" winding down tasks.
// Handlers should not throw any panic nor perform any time-consuming tasks or create channels or go routines
// that will get into any sticky blocking situation(s)
var shutdownHandlers map[string]ShutDownHandler = make(map[string]ShutDownHandler)

// A wrapper for a named shutdown handler
type ShutDownHandler struct {
	Name    string // name of the handler
	Handler func() // function to perform
}

// Execute the wrapped handler
func (h ShutDownHandler) Perform() {
	// recover/swallow any panic
	defer func() {
		if r := recover(); r != nil {
			log.Debugf("Defer Panic from shutdown handler '%s': %+v", h.Name, r)
		}
	}()
	h.Handler()
}

// Register a shutdown handler
func RegisterShutdownHandler(hnd ShutDownHandler) {
	shutdownHandlers[hnd.Name] = hnd
}

// Executes all shutdown handlers
func ExecAllShutdownHandlers() {
	for name, hnd := range shutdownHandlers {
		log.Debugf("Performing shutdown handler : '%s'", name)
		hnd.Perform()
	}
}

func RandomWaitValue(delayMult int64) (int64, error) {
	if delayMult == 0 {
		return -1, errors.New("Delay Multiplier can't be 0")
	}
	baseWait := int64(100)
	waitMax := int64(10000)
	h, d, s := time.Now().Clock()
	timeSeed := int64(h * d * s)
	r := rand.New(rand.NewSource(timeSeed))

	return r.Int63n(minimumInt64((baseWait * 2 * delayMult), waitMax)), nil
}

//find minimum between ints
func minimumInt64(firstValue int64, secondValue int64) int64 {
	//if first value is smaller, return first value
	if firstValue < secondValue {
		return firstValue
	} else {
		//if first value isn't smaller either second value is or they're equal. In either case second value will be the minimum
		return secondValue
	}

}

func Center(s string, maxlen int, fill string) string {
	if len(s) >= maxlen {
		return s
	}
	padlen := (maxlen - len(s)) / 2
	return strings.Repeat(fill, padlen) + s + strings.Repeat(fill, padlen)
}

func StripChars(str, chr string) string {
	return strings.Map(func(r rune) rune {
		if strings.IndexRune(chr, r) < 0 {
			return r
		}
		return -1
	}, str)
}

func StripSpaces(str string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsSpace(r) {
			// if the character is a space, drop it
			return -1
		}
		// else keep it in the string
		return r
	}, str)
}

// getMD5Hash returns the MD5 for the given string.
func getMD5Hash(text string) string {
	hasher := md5.New()
	hasher.Write([]byte(text))
	return hex.EncodeToString(hasher.Sum(nil))
}

// IsDevMode enables the development mode
// NOTE: Please do not remove. This is needed by the performance team
func IsDevMode() bool {
	// NOTE to prevent putting the value of the TIBCLI_DEVMODE in the executable in plain text,
	//      we put here only the MD5 of the value. To use, please set your env variable as shown below
	//      TIBCLI_DEVMODE='t!bc0 r0ckS!'
	return getMD5Hash(os.Getenv(consts.TIBCLI_DEVMODE)) == "a7da7f2df695dc68ef5ef98d4c8256b8"
}

// This method will look into the parameters and returns true if the status should be shown, false other wise
func ShouldShowStatus(c types.CommandLineContext) bool {
	return !c.IsSet("quiet")
}

// PromptUserForString interactively prompts the user for a string input
func PromptUserForString(prompt string) string {
	var v string
	fmt.Print(prompt)
	fmt.Scanf("%s\n", &v)
	return v
}

// PromptForUser interactively prompts for a username input
func PromptForUser(user string) string {
	reader := bufio.NewReader(os.Stdin)
	fmt.Print("Username(" + user + "): ")
	inputUsr, _ := reader.ReadString('\n')
	inputUsr = strings.TrimSpace(inputUsr)
	if len(inputUsr) == 0 {
		inputUsr = user
	}
	return inputUsr
}

// PromptForPassword interactively prompts for a passwrod input
func PromptForPassword() string {
	fmt.Print("Password: ")
	pwd, err := terminal.ReadPassword(int(os.Stdin.Fd()))
	if err == io.EOF {
		log.Debugf("ReadPassword error: %s", err.Error())
		os.Exit(1)
	}
	CheckError(err)
	fmt.Println()
	return string(pwd)
}

// GetDomainURL get updated domain URL.
// session.DomainUrl contains updated Domain Server Host URL, and use placeholder value if session.DomainUrl is empty.
func GetDomainURL() (string, error) {
	session, err := LoadSession(consts.OBFUSCATE_COOKIE_VALUE)
	if err != nil {
		return "", err
	}
	if session.DomainUrl != "" {
		return session.DomainUrl, nil
	}
	err, domainUrl := settings.GetPlaceHolderValue(settings.DOMAIN_SERVER_HOST_PLACEHOLDER)
	if err != nil {
		return "", err
	}
	return domainUrl, nil
}

// GetIDMConnectURL() get idm connect URL
func GetIDMConnectURL() (string, error) {
	err, idmConnectUrl := settings.GetPlaceHolderValue(settings.IDENTITY_MANAGEMENT_SERVER_HOST_PLACEHOLDER)
	if err != nil {
		return "", err
	}
	return idmConnectUrl, nil
}

// RefreshCookies will refresh local session file with new cookie values
func RefreshCookies(cookies []*http.Cookie) error {
	// if 'Set-Cookie' headers are not empty then refresh the session cookies
	if cookies != nil && len(cookies) != 0 {
		session, err := LoadSession(consts.OBFUSCATE_COOKIE_VALUE)
		if err != nil {
			return err
		}
		session.UpdateCookies(cookies, true)
	} else {
		log.Debugf("Cookies to refresh are empty, do nothing: %+v", cookies)
	}
	return nil
}

// RestCallAndCookiesRefreshHandler will do the following things:
// 1. load cookies from local session file prepare for the REST request
// 2. send request/get response for the REST call
// 3. store new cookie values from response to local session file
func RestCallAndCookiesRefreshHandler(restCallRequest *types.RestCallRequest) (*utilities.RestHandlerV3Response, error) {

	cookieJar, err := GetCookieJar(restCallRequest.Url)
	if err != nil {
		errMsg := fmt.Sprintf("Load cookies failed with error : '%+v'", err.Error())
		log.Debug(errMsg)
		return nil, errors.New(errMsg)
	}

	restHandle := utilities.NewRestHandlerV3(restCallRequest.UserId, restCallRequest.RetryAttempt)

	request := &utilities.RestHandlerV3Request{
		Url:        restCallRequest.Url.String(),
		Headers:    restCallRequest.Headers,
		Method:     restCallRequest.Method,
		CookieJar:  cookieJar,
		Body:       restCallRequest.Body,
		LogRequest: restCallRequest.LogRequest}

	response := restHandle.ExecuteAPIV3(request)
	if response.ErrorResponse == nil {
		// Persist new Cookie values get from response to local session file
		refreshCookieErr := RefreshCookies(response.Cookies)
		if refreshCookieErr != nil {
			errMsg := fmt.Sprintf("Persist cookies failed with error : '%+v'", refreshCookieErr.Error())
			log.Error(errMsg)
			return response, errors.New(errMsg)
		}
	}
	return response, nil
}

// GetUserEmail gets user email:
// 1. get user email from profile
// 2. if profile doesn't have user email, then get that from placeholder
func GetUserEmail() (string, error) {
	profile, err := LoadProfile()
	if err != nil {
		log.Debug(err.Error())
		return "", err
	}

	if len(profile.UserEmail) > 0 {
		return profile.UserEmail, nil
	}

	err, userEmail := settings.GetPlaceHolderValue(settings.USERNAME_PLACEHOLDER)
	if err != nil {
		log.Debug(err.Error())
		return "", err
	}

	return userEmail, nil
}

// GetIdmServerURL gets idm server:
// 1. get idm server from profile
// 2. if profile doesn't have idm server, then get that from placeholder
func GetIdmServerURL() (string, error) {
	profile, err := LoadProfile()
	if err != nil {
		log.Debug(err.Error())
		return "", err
	}

	if len(profile.IDMConnectURL) > 0 {
		return profile.IDMConnectURL, nil
	}

	err, idmServerURL := settings.GetPlaceHolderValue(settings.IDENTITY_MANAGEMENT_SERVER_HOST_PLACEHOLDER)
	if err != nil {
		log.Debug(err.Error())
		return "", err
	}

	return idmServerURL, nil
}

// GetKnownRegion gets known region:
// 1. get known region from profile
// 2. if profile doesn't have known region, then get that from placeholder
func GetKnownRegion() (string, error) {
	profile, err := LoadProfile()
	if err != nil {
		log.Debug(err.Error())
		return "", err
	}

	if len(profile.KnownRegion) > 0 {
		return profile.KnownRegion, nil
	}

	err, knownRegion := settings.GetPlaceHolderValue(settings.REGION_PLACEHOLDER)
	if err != nil {
		log.Debug(err.Error())
		return "", err
	}

	return knownRegion, nil
}

// GetOrgAndRegion gets org and region info from session
func GetOrgAndRegion() (string, string, error) {
	var org string
	var region string
	session, err := LoadSession(consts.OBFUSCATE_COOKIE_VALUE)
	if len(session.OrgName) > 0 {
		org = session.OrgName
	}

	if len(session.OrgDisplayName) > 0 {
		orgDisplayName := session.OrgDisplayName
		if strings.HasPrefix(orgDisplayName, org) {
			s := strings.Split(orgDisplayName, org)
			region = strings.TrimSpace(s[len(s)-1])
		}
	}
	return org, region, err
}

func GetCurrentUser() string {
	currentUser := ""
	session, err := LoadSession(consts.OBFUSCATE_COOKIE_VALUE)
	if err != nil {
		return currentUser
	}
	if len(session.UserId) > 0 {
		currentUser = session.UserId
	}

	return currentUser
}

func GetCurrentOrg() string {
	currentOrg := ""
	session, err := LoadSession(consts.OBFUSCATE_COOKIE_VALUE)
	if err != nil {
		return currentOrg
	}

	if len(session.OrgName) > 0 {
		currentOrg = session.OrgName
	}

	return currentOrg
}

func GetOrgSubscription(orgName string) (string, error) {
	subsId := ""
	session, err := LoadSession(consts.OBFUSCATE_COOKIE_VALUE)
	if session == nil || err != nil {
		return subsId, err
	}
	found := false
	for _, v := range session.OrgList {
		if v.Name == orgName {
			found = true
			subsId = v.SubscriptionId
			break
		}
	}

	if !found {
		return subsId, errors.New("Organization not found")
	}

	return subsId, nil
}

func ValidateAccessKey(key string, keys []string) bool {
	for _, v := range keys {
		if v == key {
			return true
		}
	}
	return false
}

func ConstructTunnelConnectionUrl(appDomain, appId string) string {
	return "https://" + appDomain + "/tunnel/" + appId
}
**/

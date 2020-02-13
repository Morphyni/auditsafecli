// Copyright (c) 2015-2017 TIBCO Software Inc.
// All Rights Reserved

package commands

import (
	"errors"
	"fmt"
	"net/http"
	"strings"

	"git.tibco.com/Morphyni/auditsafecli/client"
	"git.tibco.com/Morphyni/auditsafecli/consts"
	"git.tibco.com/Morphyni/auditsafecli/settings"
	"git.tibco.com/Morphyni/auditsafecli/utils"
	"github.com/urfave/cli"
	log "github.com/sirupsen/logrus"
)

// DeleteSessionFile delete session file from disk
func DeleteSessionFile() {
	session, err := settings.NewSession()
	utils.CheckError(err)
	err = session.Delete()
	utils.CheckError(err)
}

// DeleteTokenFile delete token file from disk
func DeleteTokenFile() {
	token, err := settings.NewToken()
	utils.CheckError(err)
	err = token.Delete()
	utils.CheckError(err)
}

// DeleteProfile delete profile file from disk
func DeleteProfile() {
	profile, err := settings.NewProfile()
	utils.CheckError(err)
	err = profile.Delete()
	utils.CheckError(err)
}

// CheckFeatureEnablement validates whether a particular feature is enabled or not
// via web server's Internal API -- GET /api/v1/feature/{featureName}
// func CheckFeatureEnablement(featureName string) (bool, error) {
// 	log.Debugf("Feature Name '%s' is being validated\n", featureName)
// 	if featureName == "" {
// 		log.Debug("Invalid feature name specified")
// 		return false, nil
// 	}

// 	//FIXME: Revisit this to fix proper retrieval of absolute WEB SERVER URL
// 	// set path of server url to domain server GetSandboxes
// 	domainUrl, err := utils.GetDomainURL()
// 	if err != nil {
// 		log.Debug(err.Error())
// 		return false, err
// 	}

// 	urlWebServer := strings.TrimSuffix(domainUrl, "/domain") + utils.GetWebServerFeatureAPI() + "/" + featureName

// 	log.Debugf("Initiating feature '%s' enablement against url: '%s'\n", featureName, urlWebServer)

// 	// Fill in headers appropriately
// 	headers := make(map[string]string)
// 	headers["Content-Type"] = "application/json"

// 	rh, err1 := utilities.NewRestHandler(urlWebServer, nil, "")
// 	if err1 != nil {
// 		return false, err1
// 	}

// 	log.Debugf("Sending feature '%s' enablement against url: '%s'", featureName, urlWebServer)
// 	responseBytes, err2 := rh.ExecuteGET(urlWebServer, headers, nil)
// 	if err2 != nil {
// 		return false, err2
// 	}

// 	enabledFlag := false

// 	//Populate a structure type with the byte data returned by the REST Call
// 	err3 := json.Unmarshal(responseBytes, &enabledFlag)
// 	if err3 != nil {
// 		return false, err3
// 	}

// 	if enabledFlag {
// 		log.Debugf("Feature '%s' is enabled", featureName)
// 	} else {
// 		log.Debugf("Feature '%s' is disabled", featureName)
// 	}

// 	return enabledFlag, nil
// }

// // IsValidPlatformApi validates cli version against platform api by accessing /platformapiversion
// func IsValidPlatformApi() (bool, error) {

// 	domainUrl, err := utils.GetDomainURL()
// 	if err != nil {
// 		return false, err
// 	}

// 	parsedDomainURL, err := url.Parse(domainUrl)
// 	if err == nil {
// 		parsedDomainURL.Path = "/platformapiversion"
// 	} else {
// 		return false, err
// 	}

// 	tccUrlForPlatformVersion := parsedDomainURL.String()
// 	log.Debugf("tccURL to GET PlatformVersion: %s", tccUrlForPlatformVersion)

// 	noRedirectMarker := errors.New("my-redirect-marker")

// 	httpClient := &http.Client{CheckRedirect: func(req *http.Request, via []*http.Request) error {
// 		return noRedirectMarker
// 	}}
// 	request, err := http.NewRequest("GET", tccUrlForPlatformVersion, nil)
// 	if err != nil {
// 		log.Debugf("GET '%s' failed with error: %s", tccUrlForPlatformVersion, err.Error())
// 		return false, err
// 	}

// 	resp, err := httpClient.Do(request)
// 	if err != nil && !strings.Contains(err.Error(), noRedirectMarker.Error()) {
// 		log.Debugf("Request '%+v' failed with error: %s", request, err.Error())
// 		return false, err
// 	}
// 	defer resp.Body.Close()

// 	//there's no version to parse unless we get 200 status code
// 	if resp.StatusCode != http.StatusOK {
// 		return false, errors.New("Server responded with " + resp.Status)
// 	}

// 	bytes, err := ioutil.ReadAll(resp.Body)
// 	if err != nil {
// 		log.Debugf("Read resp.Body '%+v' failed with error: %s", resp.Body, err.Error())
// 		return false, err
// 	}

// 	platformApiVersion := string(bytes)

// 	log.Debugf("PlatformApiVersion received from '%s': %s", tccUrlForPlatformVersion, platformApiVersion)

// 	splitPlatformApiVersion := strings.Split(platformApiVersion, ".")
// 	splitCliVersion := strings.Split(consts.CLI_VERSION, ".")

// 	log.Debugf("platformApiVersion: '%s' consts.CLI_VERSION: '%s'", platformApiVersion, consts.CLI_VERSION)

// 	// compare the major version of cli and platform api version
// 	if splitCliVersion[0] != splitPlatformApiVersion[0] {
// 		log.Debugf("Platform major version '%s' doesn't match CLI major version '%s'", splitPlatformApiVersion[0], splitCliVersion[0])
// 		return false, nil
// 	}
// 	return true, nil
// }

// // TaLogin performs login to TIBCO Accounts with username and password
// func TaLogin(url, user, password string) (*types.OAResponse, error) {

// 	oauth, err := client.NewOAuthClient(url)
// 	if err != nil {
// 		return nil, err
// 	}
// 	err, clientId := settings.GetPlaceHolderValue(settings.TIBCO_ACCOUNTS_CLIENTID_PLACEHOLDER)
// 	if err != nil {
// 		log.Debug(err)
// 		utils.CheckError(errors.New("TIBCO Accounts' client id not set"))
// 	}

// 	resp, err := oauth.Login(types.AuthRequest{Username: user, Pwd: password, ClientId: clientId})
// 	if err == nil {
// 		token, e := settings.NewToken()
// 		if e != nil {
// 			log.Errorf("NON-FATAL: Couldn't create session file for login token: %v", e)
// 		}

// 		// here we keep TA accessToken in a Cookie just want to get benefit of reusing the isValid() func in settingsfile.go which checks the cookie expired or not.
// 		taTokenCookie := &http.Cookie{Name: settings.ACCESS_TOKEN_KEY_NAME, Value: resp.AccessToken, //TODO switch to RefreshToken
// 			Expires: time.Now().UTC().Add(time.Duration(resp.ExpiresIn) * time.Second)}

// 		token.AccessToken = taTokenCookie

// 		if utils.GetEnvParam(consts.DONT_PERSIST) == "" {
// 			e = token.Write(consts.OBFUSCATE_COOKIE_VALUE) //obfuscate Token
// 			if e != nil {
// 				log.Errorf("NON-FATAL: Couldn't persist the login token to disk: %v", e)
// 			} else {
// 				log.Debugf("Persisted the login token to disk.")
// 			}
// 		} else {
// 			log.Infof("No OAuth token persisted since environment variable '%s' wasn't set.", consts.DONT_PERSIST)
// 		}
// 	}
// 	return resp, err
// }

// IdmLogin performs actual login with IdentityManagementServer
func IdmLogin(idmURL, userEmail, taAccessToken string, orgInfo types.OrgInfo, loginFlag bool) error {

	idmClient, err := client.NewIdentityManagementServer()
	if err != nil {
		return err
	}
	idmLoginResponse, err := idmClient.Login(taAccessToken, orgInfo, loginFlag)
	if err != nil {
		//taAccessToken deleted for unsuccessful login.
		DeleteTokenFile()
		return err
	}
	log.Debugf("IDM Login Response received: '%+v'", idmLoginResponse)

	dsClient, err := client.NewDomainServerV2(idmLoginResponse.DomainUrl)
	if err != nil {
		return err
	}
	defaultSandbox, _, err := dsClient.GetDefaultSandbox()
	if err != nil {
		return err
	}

	if len(idmLoginResponse.DomainUrl) > 0 {
		idmURL = idmLoginResponse.DomainUrl
	}

	return storeProfileAndSessions(idmLoginResponse, defaultSandbox, userEmail, idmURL)
}

func storeProfileAndSessions(idmLoginResponse *types.IDMLoginResponse, defaultSandbox *types.DomainServerSandboxBean, userEmail string, idmURL string) error {

	// save profile
	profile, err := settings.NewProfile()
	if err != nil {
		return err
	}
	profile.IDMConnectURL = idmURL
	profile.UserEmail = userEmail
	profile.KnownRegion = idmLoginResponse.KnownRegion
	err = profile.Write()
	if err != nil {
		return err
	}
	log.Debugf("User Profile saved successfully with contents: '%+v'", profile)

	// save session
	session, err := settings.NewSession()
	if err != nil {
		return err
	}
	// load session value
	session.Read(consts.OBFUSCATE_COOKIE_VALUE)

	session.FirstName = idmLoginResponse.FirstName
	session.LastName = idmLoginResponse.LastName
	session.UserName = idmLoginResponse.UserName
	session.UserId = idmLoginResponse.UserId
	session.OrgName = idmLoginResponse.OrgName
	session.TS = idmLoginResponse.TS

	session.DomainUrl = idmLoginResponse.DomainUrl
	session.OrgDisplayName = idmLoginResponse.OrgDisplayName
	session.OrgList = idmLoginResponse.OrgList

	session.DefaultSandboxName = defaultSandbox.SandboxName
	session.DefaultSandboxOrganizationId = defaultSandbox.OrganizationId

	err = session.Write(consts.OBFUSCATE_COOKIE_VALUE)
	if err != nil {
		return err
	}
	log.Debugf("User Session saved successfully.")

	return nil

}

// CheckPlatformVersionAndLogin is a before action for all commands which enforces user to be logged-in first
//ensure that platform API version is correct and user is logged in
func CheckPlatformVersionAndLogin(c *cli.Context) error {
	//	validate tibcli api version compatibility with platform api version

	log.Debug("Validate tibcli version and check login...")

	if isValid, err := IsValidPlatformApi(); err != nil {
		if strings.Contains(err.Error(), "Session.orgList") {
			DeleteSessionFile()
			DeleteTokenFile()
			return checkLogin(c)
		}
		// utils.CheckError(errors.New(fmt.Sprintf("Troposphere platform services api version validating failed with error : %s", err.Error())))
	} else {
		if isValid == false {
			// utils.CheckError(errors.New("troposphere platform services api version mismatched with tibcli version, please download a new tibcli command line tool from web page."))
		}
	}
	return checkLogin(c)
}

//ensure user is logged in
func checkLogin(c *cli.Context) error {

	//check that branded values in tibcli, including domainURL match saved local profile
	profile, session, token, err := utils.LoadSettings()
	utils.CheckError(err)

	// if 'old-style' profile doesn't have version field or version field has wrong version number then wipe out all profile/session/token and start from scratch
	if profile.Version != consts.CLI_VERSION {

		utils.CheckError(profile.Delete())
		utils.CheckError(session.Delete())
		utils.CheckError(token.Delete())

		session, err = utils.LoadSession(consts.OBFUSCATE_COOKIE_VALUE)
		utils.CheckError(err)
		profile, err = utils.LoadProfile()
		utils.CheckError(err)
		token, err = utils.LoadToken(consts.OBFUSCATE_COOKIE_VALUE)
		utils.CheckError(err)
	}

	// get idm server url from placeholder
	err, idmServerURL := settings.GetPlaceHolderValue(settings.IDENTITY_MANAGEMENT_SERVER_HOST_PLACEHOLDER)
	if err != nil || len(idmServerURL) == 0 {
		log.Debug(err.Error())
		// utils.CheckError(errors.New("Identity-Management Server URL is not set via placeholder."))
	}

	// get user email from placeholder
	err, userEmail := settings.GetPlaceHolderValue(settings.USERNAME_PLACEHOLDER)
	if err != nil || len(userEmail) == 0 {
		log.Debug(err.Error())
		// utils.CheckError(errors.New("Username is not set via placeholder."))
	}

	// check user email in profile
	if len(profile.UserEmail) > 0 && profile.UserEmail != userEmail {
		log.Debugf("profile.userEmail: %s, userEmail read from placeholder is: %s", profile.UserEmail, userEmail)
		userEmail = profile.UserEmail
	}

	// check idm server url in profile
	if len(profile.IDMConnectURL) > 0 && profile.IDMConnectURL != idmServerURL {
		log.Debugf("profile.idmServerUrl: %s, idm server URL read from placeholder is: %s", profile.IDMConnectURL, idmServerURL)
		idmServerURL = profile.IDMConnectURL
	}

	//we may prompt user here for password only if this is NOT the login command.  That command does prompt on its own
	promptForPassword := c.Command.Name != "login"

	isSessionValid := CheckCookiesIsValid(session.Cookies, settings.SESSION_FILENAME)
	log.Debugf("session cookies is valid ? : '%+v'", isSessionValid)

	// check cookies of session are still-valid or not
	if !isSessionValid {
		log.Debug("session cookies get expired")
		// load TA access token
		loadedAccessToken, er := utils.LoadToken(consts.OBFUSCATE_COOKIE_VALUE)
		utils.CheckError(er)

		if CheckCookiesIsValid([]*http.Cookie{loadedAccessToken.AccessToken}, settings.TOKEN_FILE_NAME) {
			log.Debug("Session cookies missing or expired, trying still-valid access token")

			// Login to IDM again to refresh session with the still-valid TA access token
			// Re-login, user won't input username/password, so LoginFlag set to false
			orgInfo := types.OrgInfo{
				AccountName: c.String("org"),
				Region:      c.String("region"),
			}
			err = IdmLogin(idmServerURL, userEmail, loadedAccessToken.AccessToken.Value, orgInfo, false)
			if err != nil {
				log.Debugf("Refresh session rejected by IDM Server %+v ", err)
				utils.CheckError(err)
				return err
			}

		} else { // TA access token and IDM session both expired
			if !promptForPassword { // for login command
				return errors.New("No session cookies, no access token; need to log in")
			}

			log.Debug("User is not logged-in or session has expired. Hence initiating login.")
			fmt.Println("User is not logged-in or session has expired.")

			// get TA URL from placeholder
			err, taURL := settings.GetPlaceHolderValue(settings.TIBCO_ACCOUNTS_URL_PLACEHOLDER)
			if err != nil {
				log.Debug(err.Error())
				// utils.CheckError(errors.New("TIBCO Accounts url not set via placeholder."))
			}
			// read user/password from user input
			userEmail = utils.PromptForUser(userEmail)
			password := utils.PromptForPassword()

			// Do TA login
			accessToken, err := TaLogin(taURL, userEmail, password)
			if err != nil {
				log.Debugf("Refresh accessToken rejected by TA Server %+v ", err)
				utils.CheckError(err)
				return err
			}
			// Do IDM login
			err = IdmLogin(idmServerURL, userEmail, accessToken.AccessToken, types.OrgInfo{}, true)
			if err != nil {
				log.Debugf("Refresh session rejected by IDM Server %+v ", err)
				utils.CheckError(err)
				return err
			}
		}
	}
	return nil
}

// Login implements command "login"
func Login(c *cli.Context) {
	if !CheckLoginCommandFlags(c) {
		return
	}

	settings.PrintPlaceholderValues()

	orgInfo := types.OrgInfo{
		AccountName: c.String("org"),
		Region:      c.String("region"),
	}
	password := c.String("password")
	inputUser := c.String("username")
	taURL := ""
	idmServerURL := ""

	userEmail, err := utils.GetUserEmail()
	if err != nil || len(userEmail) == 0 {
		log.Debug(err.Error())
		// utils.CheckError(errors.New("Username is not set."))
	}

	if err, value := settings.GetPlaceHolderValue(settings.TIBCO_ACCOUNTS_URL_PLACEHOLDER); err == nil {
		taURL = value
	} else {
		log.Debug(err.Error())
		// utils.CheckError(errors.New("TIBCO Accounts URL is not set."))
	}

	idmServerURL, err = utils.GetIDMConnectURL()
	if err != nil {
		log.Debug(err.Error())
		// utils.CheckError(errors.New("Identity-Management Server URL is not set."))
	}

	if !c.IsSet("username") && !c.IsSet("password") {
		inputUser = utils.PromptForUser(userEmail)
	} else if !c.IsSet("username") && c.IsSet("password") {
		inputUser = userEmail
	}

	if CheckPlatformVersionAndLogin(c) == nil {
		cOrg, cRegion, err := utils.GetOrgAndRegion()
		if err != nil {
			log.Debug(err.Error())
			utils.CheckError(errors.New("Failed to retrieve current organization and region information. "))
			return
		}

		if inputUser == userEmail {
			if c.IsSet("org") && c.IsSet("region") {
				if cOrg == orgInfo.AccountName && cRegion == orgInfo.Region {
					fmt.Println("User is already logged in. ")
					return
				}
			} else {
				fmt.Println("User is already logged in. ")
				return
			}
		}

	}

	if !c.IsSet("password") {
		password = utils.PromptForPassword()
	}

	// do login
	token, err := TaLogin(taURL, inputUser, password)
	utils.CheckError(err)

	err = IdmLogin(idmServerURL, inputUser, token.AccessToken, orgInfo, true)

	utils.CheckError(err)
	return
}

// Logout implements the logout function
func Logout(_ *cli.Context) {
	DeleteSessionFile()
	DeleteTokenFile()
	fmt.Print("User logged out successfully from Atmosphere.\n")
}

// // GetSandboxId returns the sandbox identifier corresponding to sandbox name
// func GetSandboxId(sandboxName string) (string, *types.DomainServerSandboxBean, error) {

// 	log.Debugf("Getting Sandbox Id for name '%s'", sandboxName)

// 	// Get Sandbox list via Domain Server REST API
// 	ds, err := client.NewDomainServer()
// 	if err != nil {
// 		return "", nil, err
// 	}

// 	// Get all sandboxes for current organization
// 	allSandboxesResponse, err := ds.GetOrgSandboxes()
// 	if err != nil {
// 		log.Debug("Error getting all sandboxes")
// 		return "", nil, err
// 	}

// 	matchingSandboxBean := types.DomainServerSandboxBean{}
// 	matchingSandboxId := ""
// 	matchFound := false

// 	// Loop through all the sandboxes for the current user
// 	for _, sandbox := range allSandboxesResponse.Sandboxes {
// 		if sandboxName == sandbox.SandboxName {
// 			matchingSandboxId = sandbox.Id
// 			matchingSandboxBean = sandbox
// 			matchFound = true
// 			msg := fmt.Sprintf("Input Sandbox '%s' matched with '%s'\n", sandboxName, sandbox.SandboxName)
// 			log.Debug(msg)
// 			break
// 		}
// 	}

// 	// matchFound = false --> indicates the sandbox in question is not found in the list for current user
// 	if !matchFound {
// 		msg := fmt.Sprintf("The sandbox '%s' is not found.", sandboxName)
// 		log.Debug(msg)
// 		return "", nil, errors.New(msg)
// 	}

// 	return matchingSandboxId, &matchingSandboxBean, nil
// }

// // GetSandboxInfo return the sandboxName and sandboxId or an error
// func GetSandboxInfo(c types.CommandLineContext, session *settings.Session) (string, string, error) {

// 	log.Debug("Getting Sandbox Info")

// 	sandboxName := c.String("sandbox")

// 	if !c.IsSet("sandbox") {
// 		// use the default sandbox for this user
// 		sandboxName = session.DefaultSandboxName
// 		log.Debugf("Using default sandbox name '%s'", sandboxName)
// 	}

// 	// Get sandboxId for the sandboxName
// 	//FIXME: Replaced lookup in the session w/ a call to DOMAIN SERVER for one of user-specific multiple sandboxes - Revisit, if needed
// 	//sandboxId, ok := session.Sandboxes[sandboxName]

// 	sandboxId, _, err := GetSandboxId(sandboxName)
// 	if err != nil {
// 		return "", "", err
// 	}
// 	log.Debugf("sandboxId for sandboxName '%s' found value: '%s'", sandboxName, sandboxId)
// 	return sandboxName, sandboxId, nil
// }

// func GetApplicationBean(sbscId, appName string) (bool, *types.DomainServerApplicationBean, error) {
// 	if sbscId == consts.CURRENT_SBSC_VALUE {
// 		return GetApplicationId(appName)
// 	}

// 	return GetApplication(sbscId, appName)
// }

// // GetApplicationId returns the application identifier corresponding to application name
// func GetApplicationId(appName string) (bool, *types.DomainServerApplicationBean, error) {
// 	log.Debugf("Getting Application Identifier for name '%s'", appName)

// 	// Get Application list via Domain Server REST API
// 	ds, err := client.NewDomainServer()
// 	if err != nil {
// 		return false, nil, err
// 	}

// 	// Get application details
// 	appBean, err, applicationNotFound := ds.GetApplicationDetails(appName, consts.DEFAULT_SANDBOX)
// 	if applicationNotFound == true {
// 		return false, appBean, fmt.Errorf("Application '%s' is not found. Please re-enter a valid application name.\n", appName)
// 	} else if appBean != nil {
// 		return true, appBean, nil
// 	} else {
// 		return false, appBean, err
// 	}
// }

// // GetApplication returns the appBean corresponding to sbscId and application name
// func GetApplication(sbscId, appName string) (bool, *types.DomainServerApplicationBean, error) {
// 	log.Debugf("Getting Application Identifier for name '%s'", appName)

// 	// Get Application list via Domain Server REST API
// 	ds, err := client.NewDomainServer()
// 	if err != nil {
// 		return false, nil, err
// 	}

// 	// Get applications
// 	listResponse, err := ds.GetAllApplicationsBySbscId(sbscId)
// 	if err != nil {
// 		return false, nil, err
// 	}

// 	for _, appBean := range listResponse.ApplicationBeans {
// 		if appName == appBean.ApplicationName {
// 			errMsg := fmt.Sprintf("Application '%s' is not found. Please re-enter a valid application name.\n", appName)
// 			return true, &appBean, errors.New(errMsg)
// 		}
// 	}

// 	return false, nil, err
// }

// // CheckCookiesIsValid checks all cookies are valid/expired
// func CheckCookiesIsValid(cookies []*http.Cookie, fileName string) bool {
// 	if cookies == nil || len(cookies) == 0 {
// 		log.Debug("Cookies of session file are empty")
// 		return false
// 	}
// 	if fileName == settings.TOKEN_FILE_NAME {
// 		for _, cookie := range cookies {
// 			if cookie == nil {
// 				log.Debug("One of the session cookies is empty")
// 				return false
// 			}
// 			if !cookie.Expires.IsZero() && cookie.Expires.Before(time.Now().UTC()) {
// 				// Cookie expiration is set and before current time means expired
// 				return false
// 			}
// 		}
// 	} else if fileName == settings.SESSION_FILENAME { // cookies in session file are coming from IDM which don't have 'Expires' field so we need another way to test they are valid or not
// 		// we use the get default sandbox call on domain server to check if the cookies
// 		dsClient, err := client.NewDomainServer()
// 		if err != nil {
// 			log.Errorf("Initializing DomainServer client instance on error: %s", err.Error())
// 			return false
// 		}
// 		_, httpCode, err := dsClient.GetDefaultSandbox()
// 		if err != nil {
// 			if httpCode == 599 && strings.Contains(err.Error(), "419") { // the backend code set 599 code in the response httpCode and the 419 code can be found from error msg
// 				log.Debugf("Cookies in session file get invalid as we got 419 error while accessing backend: %s", err.Error())
// 			} else {
// 				log.Debugf("Validating session cookies failed on errors other then 419: %s", err.Error())
// 			}
// 			return false
// 		}
// 	} else {
// 		log.Errorf("Unknown file name: %s", fileName)
// 		return false
// 	}
// 	return true
// }

// func clean() {
// 	DeleteProfile()
// 	DeleteSessionFile()
// 	DeleteTokenFile()
// }

// // CheckLoginCommandFlags checks login command flags
// func CheckLoginCommandFlags(c *cli.Context) bool {
// 	if c.IsSet("username") && !c.IsSet("password") {
// 		fmt.Println("Please provide password if username is specified. \n ")
// 		fmt.Println("Example: ")
// 		fmt.Println("  tibcli login -u yourname@example.com -p yourpassword \n ")
// 		return false
// 	}
// 	if (c.IsSet("org") && !c.IsSet("region")) || (!c.IsSet("org") && c.IsSet("region")) {
// 		utils.CheckError(errors.New("Please provide organization name with region info. Either organization name or region is missing. "))
// 		return false
// 	}
// 	return true
// }

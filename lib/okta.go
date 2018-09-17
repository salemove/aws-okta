package lib

import (
	"encoding/json"
	"errors"
	"time"

	"github.com/99designs/keyring"
	log "github.com/Sirupsen/logrus"
	"github.com/aws/aws-sdk-go/service/sts"
)

const (
	OktaServer = "okta.com"
)

type OktaCreds struct {
	Organization string
	Username     string
	Password     string
}

func (c *OktaCreds) Validate() error {
	// OktaSAMLClient assumes we're doing some AWS SAML calls, but Validate doesn't
	o, err := NewOktaSAMLClient(*c, "", nil)
	if err != nil {
		return err
	}

	if err := o.AuthenticateUser(); err != nil {
		return err
	}

	return nil
}

type OktaClient interface {
	AuthenticateProfile(profileARN string, duration time.Duration) (sts.Credentials, error)
}

type OktaProvider struct {
	Keyring         keyring.Keyring
	ProfileARN      string
	SessionDuration time.Duration
	OktaAwsSAMLUrl  string
	OIDCAppID       string
}

func (p *OktaProvider) Retrieve() (sts.Credentials, string, error) {
	log.Debug("using okta provider")
	item, err := p.Keyring.Get("okta-creds")
	if err != nil {
		log.Debugf("couldnt get okta creds from keyring: %s", err)
		return sts.Credentials{}, "", err
	}

	var oktaCreds OktaCreds
	if err = json.Unmarshal(item.Data, &oktaCreds); err != nil {
		return sts.Credentials{}, "", errors.New("Failed to get okta credentials from your keyring.  Please make sure you have added okta credentials with `aws-okta add`")
	}

	oktaClient, err := p.getOktaClient(oktaCreds)
	if err != nil {
		return sts.Credentials{}, "", err
	}

	creds, err := oktaClient.AuthenticateProfile(p.ProfileARN, p.SessionDuration)
	if err != nil {
		return sts.Credentials{}, "", err
	}

	return creds, oktaCreds.Username, err
}

func (p *OktaProvider) getOktaClient(oktaCreds OktaCreds) (OktaClient, error) {
	if p.OIDCAppID != "" {
		log.Debug("OIDC App ID set. Using OICD client.")
		return NewOktaOIDCClient(oktaCreds, p.OIDCAppID)
	}
	log.Debug("Using SAML client")
	return NewOktaSAMLClient(oktaCreds, p.OktaAwsSAMLUrl, p.Keyring)
}

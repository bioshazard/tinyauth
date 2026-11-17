package service

// Directory-owned canonical identities shared by OIDC and ForwardAuth.
import (
	"encoding/json"
	"fmt"
	"net"
	"slices"
	"time"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/tinyauthapp/tinyauth/internal/model"
	"github.com/tinyauthapp/tinyauth/internal/utils"
)

func (s *OIDCService) ResolveHousehold(u *model.UserContext, client string) error {
	return ResolveHousehold(s.config, u, s.config.Household.ClientGroups[client])
}

// ResolveHousehold accepts only an authenticated upstream identity and explicit app groups.
func ResolveHousehold(config *model.Config, u *model.UserContext, required []string) error {
	if !config.Household.Enabled {
		return nil
	}
	binding := &model.HouseholdIdentity{Provider: u.GetProviderID(), Username: u.GetUsername()}
	if u.IsOAuth() {
		binding.Subject = u.OAuth.Sub
		binding.Username = ""
	}
	if !u.Authenticated || len(required) == 0 {
		return fmt.Errorf("household app grant missing")
	}
	person, err := lookupHousehold(config, binding, required)
	if err != nil {
		return err
	}
	if u.ExpectedPersonID != nil && *u.ExpectedPersonID != person.Household.PersonID {
		return fmt.Errorf("SSO session identity changed owner; authenticate again")
	}
	u.Household = person.Household
	// Return directory-owned attributes regardless of which login method was used.
	if u.IsOAuth() {
		u.OAuth.Username = person.PreferredUsername
		u.OAuth.Name = person.Name
		u.OAuth.Email = person.Email
		u.OAuth.Groups = person.Groups
	}
	if u.IsLDAP() {
		u.LDAP.Username = person.PreferredUsername
		u.LDAP.Name = person.Name
		u.LDAP.Email = person.Email
		u.LDAP.Groups = person.Groups
	}
	return nil
}

func (s *OIDCService) RevalidateHousehold(info *UserinfoResponse, client string) error {
	if !s.config.Household.Enabled {
		return nil
	}
	if info.Household == nil {
		return fmt.Errorf("missing canonical identity")
	}
	required := s.config.Household.ClientGroups[client]
	if len(required) == 0 {
		return fmt.Errorf("household client grant missing")
	}
	current, err := lookupHousehold(s.config, info.Household, required)
	if err != nil {
		return err
	}
	if current.Household.PersonID != info.Household.PersonID {
		return fmt.Errorf("identity binding changed owner")
	}
	current.Sub = info.Sub
	*info = *current
	return nil
}

func lookupHousehold(config *model.Config, binding *model.HouseholdIdentity, required []string) (*UserinfoResponse, error) {
	cfg := config.Household
	// Separate short-lived service connection: never shares the password-bind connection.
	conn, err := ldap.DialURL(config.LDAP.Address, ldap.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}))
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	conn.SetTimeout(5 * time.Second)
	if err = conn.Bind(config.LDAP.BindDN, utils.GetSecret(config.LDAP.BindPassword, config.LDAP.BindPasswordFile)); err != nil {
		return nil, err
	}
	result, err := conn.Search(ldap.NewSearchRequest(config.LDAP.BaseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 5, false, "(objectClass=person)", []string{"uid", "mail", "cn", cfg.PersonAttribute, cfg.IdentityAttribute}, nil))
	if err != nil {
		return nil, err
	}
	var found *ldap.Entry
	seenIDs := map[string]bool{}
	issuer := ""
	if binding.Provider != "ldap" {
		issuer = cfg.ProviderIssuers[binding.Provider]
		if issuer == "" || binding.Subject == "" {
			return nil, fmt.Errorf("unknown provider or empty subject")
		}
	}
	if binding.Provider == "ldap" && binding.Username == "" {
		return nil, fmt.Errorf("empty LDAP identity")
	}
	for _, entry := range result.Entries {
		ids := entry.GetAttributeValues(cfg.PersonAttribute)
		if len(ids) > 1 {
			return nil, fmt.Errorf("multiple person identifiers")
		}
		if len(ids) == 1 {
			if ids[0] == "" || seenIDs[ids[0]] {
				return nil, fmt.Errorf("duplicate person identifier")
			}
			seenIDs[ids[0]] = true
		}
		match := false
		if binding.Provider == "ldap" {
			match = entry.GetAttributeValue("uid") == binding.Username
		} else {
			for _, raw := range entry.GetAttributeValues(cfg.IdentityAttribute) {
				var pair []string
				if err := json.Unmarshal([]byte(raw), &pair); err != nil || len(pair) != 2 {
					return nil, fmt.Errorf("malformed directory identity binding")
				}
				if pair[0] == issuer && pair[1] == binding.Subject {
					match = true
				}
			}
		}
		if match {
			if found != nil {
				return nil, fmt.Errorf("ambiguous identity binding")
			}
			found = entry
		}
	}
	if found == nil {
		return nil, fmt.Errorf("unmapped identity")
	}
	id := found.GetAttributeValue(cfg.PersonAttribute)
	if id == "" {
		return nil, fmt.Errorf("person has no stable identifier")
	}
	groupsResult, err := conn.Search(ldap.NewSearchRequest(config.LDAP.BaseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 5, false, fmt.Sprintf("(&(objectClass=groupOfNames)(member=%s))", ldap.EscapeFilter(found.DN)), []string{"cn"}, nil))
	if err != nil {
		return nil, err
	}
	groups := []string{}
	allowed := len(required) == 0
	for _, entry := range groupsResult.Entries {
		name := entry.GetAttributeValue("cn")
		groups = append(groups, name)
		if slices.Contains(required, name) {
			allowed = true
		}
	}
	if !allowed {
		return nil, fmt.Errorf("person lacks required app group")
	}
	copyBinding := *binding
	copyBinding.PersonID = id
	copyBinding.Groups = groups
	return &UserinfoResponse{Household: &copyBinding, PreferredUsername: found.GetAttributeValue("uid"), Email: found.GetAttributeValue("mail"), Name: found.GetAttributeValue("cn"), Groups: groups, UpdatedAt: time.Now().Unix()}, nil
}

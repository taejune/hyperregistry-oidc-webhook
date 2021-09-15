package harbor_go

import (
	"encoding/json"
	"fmt"
	"hyperregistry-oidc-webhook/pkg/habor-go/model"
	"io/ioutil"
	"net/http"
	"strconv"
)

type UserRole int

const (
	Admin UserRole = 1 + iota
	Maintainer
	Developer
	Guest
	LimitedGuest
)

func (c *RestClient) ExistProject(name string) (bool, error) {
	req := RequestForm{
		Method:  http.MethodHead,
		Path:    "projects",
		Params:  map[string]string{"project_name": name},
		Headers: nil,
		Payload: nil,
	}

	res, err := c.client.Submit(req)
	switch res.StatusCode {
	case http.StatusOK:
		return true, nil
	case http.StatusNotFound:
		return false, NewHarborError(ErrorNotFound, "")
	case http.StatusInternalServerError:
		return false, NewHarborError(ErrorInternal, "")
	}

	return false, NewHarborError(ErrorUnknown, err.Error())
}

func (c *RestClient) NewProject(name string, public bool) (bool, error) {
	req := RequestForm{
		Method:  http.MethodPost,
		Path:    "projects",
		Params:  nil,
		Headers: map[string]string{"content-type": "application/json"},
		Payload: map[string]interface{}{"project_name": name},
	}

	res, err := c.client.Submit(req)
	switch res.StatusCode {
	case http.StatusCreated:
		return true, nil
	case http.StatusBadRequest:
		return false, NewHarborError(ErrorBadRequest, "")
	case http.StatusUnauthorized:
		return false, NewHarborError(ErrorUnauthorized, "")
	case http.StatusConflict:
		return false, NewHarborError(ErrorConflict, "")
	case http.StatusInternalServerError:
		return false, NewHarborError(ErrorInternal, "")
	}
	return false, NewHarborError(ErrorUnknown, err.Error())
}

func (c *RestClient) GetProject(name string) (*model.Project, error) {
	req := RequestForm{
		Method:  http.MethodGet,
		Path:    fmt.Sprintf("projects/%s", name),
		Params:  nil,
		Headers: nil,
		Payload: nil,
	}

	res, err := c.client.Submit(req)
	defer res.Body.Close()
	switch res.StatusCode {
	case http.StatusOK:
		dat, err := ioutil.ReadAll(res.Body)
		if err != nil {
			return nil, NewHarborError(ErrorUnknown, err.Error())
		}
		p := model.Project{}
		err = json.Unmarshal(dat, &p)
		if err != nil {
			return nil, err
		}

		return &p, nil
	case http.StatusUnauthorized:
		return nil, NewHarborError(ErrorUnauthorized, "Unauthorized request")
	case http.StatusInternalServerError:
		return nil, NewHarborError(ErrorInternal, "Internal server error")
	}

	return nil, NewHarborError(ErrorUnknown, err.Error())
}

func (c *RestClient) AddProjectMember(projectId int, userId string, role UserRole) (bool, error) {
	req := RequestForm{
		Method:  http.MethodGet,
		Path:    fmt.Sprintf("projects/%s/members", strconv.Itoa(projectId)),
		Params:  nil,
		Headers: map[string]string{"content-type": "application/json"},
		Payload: map[string]interface{}{
			"role_id": role,
			"member_user": map[string]string{
				"username": userId,
			},
		},
	}

	res, err := c.client.Submit(req)
	switch res.StatusCode {
	case http.StatusCreated:
		return true, nil
	case http.StatusBadRequest:
		return true, NewHarborError(ErrorBadRequest, "Illegal format of project member or project id is invalid, or LDAP DN is invalid.")
	case http.StatusUnauthorized:
		return true, NewHarborError(ErrorUnauthorized, "User need to log in first.")
	case http.StatusForbidden:
		return true, NewHarborError(ErrorForbidden, "User in session does not have permission to the project.")
	case http.StatusConflict:
		return true, NewHarborError(ErrorConflict, "A user group with same group name already exist or an LDAP user group with same DN already exist.")
	case http.StatusInternalServerError:
		return true, NewHarborError(ErrorInternal, "Unexpected internal errors.")
	}

	return false, NewHarborError(ErrorUnknown, err.Error())
}

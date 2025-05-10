package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/supabase/auth/internal/api/apierrors"
	"github.com/supabase/auth/internal/crypto"
	"github.com/supabase/auth/internal/models"
	"github.com/supabase/auth/internal/storage"
)

// MagicLinkParams holds the parameters for a magic link request
type MagicLinkParams struct {
	Email               string                 `json:"email"`
	Data                map[string]interface{} `json:"data"`
	CodeChallengeMethod string                 `json:"code_challenge_method"`
	CodeChallenge       string                 `json:"code_challenge"`
}

func (p *MagicLinkParams) Validate(a *API) error {
	if p.Email == "" {
		return apierrors.NewUnprocessableEntityError(apierrors.ErrorCodeValidationFailed, "Password recovery requires an email")
	}
	var err error
	p.Email, err = a.validateEmail(p.Email)
	if err != nil {
		return err
	}
	if err := validatePKCEParams(p.CodeChallengeMethod, p.CodeChallenge); err != nil {
		return err
	}
	return nil
}

// MagicLink sends a recovery email
func (a *API) MagicLink(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	db := a.db.WithContext(ctx)
	config := a.config

	fmt.Println("MagicLink")

	if !config.External.Email.Enabled {
		return apierrors.NewUnprocessableEntityError(apierrors.ErrorCodeEmailProviderDisabled, "Email logins are disabled")
	}

	if !config.External.Email.MagicLinkEnabled {
		return apierrors.NewUnprocessableEntityError(apierrors.ErrorCodeEmailProviderDisabled, "Login with magic link is disabled")
	}

	params := &MagicLinkParams{}
	jsonDecoder := json.NewDecoder(r.Body)
	err := jsonDecoder.Decode(params)
	if err != nil {
		fmt.Println("MagicLink error (could not read verification params)", err)
		return badRequestError(apierrors.ErrorCodeBadJSON, "Could not read verification params: %v", err).WithInternalError(err)
	}

	if err := params.Validate(); err != nil {
		fmt.Println("MagicLink error (could not validate params)", err)
		return err
	}

	if params.Data == nil {
		params.Data = make(map[string]interface{})
	}

	flowType := getFlowFromChallenge(params.CodeChallenge)

	var isNewUser bool
	aud := a.requestAud(ctx, r)
	user, err := models.FindUserByEmailAndAudience(db, params.Email, aud)
	if err != nil {
		if models.IsNotFoundError(err) {
			fmt.Println("MagicLink user not found")
			isNewUser = true
		} else {
			fmt.Println("MagicLink error (database error finding user)", err)
			return apierrors.NewInternalServerError("Database error finding user").WithInternalError(err)
		}
	}
	if user != nil {
		fmt.Println("MagicLink user found")
		isNewUser = !user.IsConfirmed()
	}
	if isNewUser {
		// User either doesn't exist or hasn't completed the signup process.
		// Sign them up with temporary password.
		password := crypto.GeneratePassword(config.Password.RequiredCharacters, 33)

		signUpParams := &SignupParams{
			Email:               params.Email,
			Password:            password,
			Data:                params.Data,
			CodeChallengeMethod: params.CodeChallengeMethod,
			CodeChallenge:       params.CodeChallenge,
		}
		newBodyContent, err := json.Marshal(signUpParams)
		if err != nil {
			// SignupParams must always be marshallable
			panic(fmt.Errorf("failed to marshal SignupParams: %w", err))
		}
		r.Body = io.NopCloser(strings.NewReader(string(newBodyContent)))
		r.ContentLength = int64(len(string(newBodyContent)))

		fakeResponse := &responseStub{}
		if config.Mailer.Autoconfirm {
			fmt.Println("MagicLink autoconfirm")
			// signups are autoconfirmed, send magic link after signup
			if err := a.Signup(fakeResponse, r); err != nil {
				return err
			}
			newBodyContent := &SignupParams{
				Email:               params.Email,
				Data:                params.Data,
				CodeChallengeMethod: params.CodeChallengeMethod,
				CodeChallenge:       params.CodeChallenge,
			}
			metadata, err := json.Marshal(newBodyContent)
			if err != nil {
				// SignupParams must always be marshallable
				panic(fmt.Errorf("failed to marshal SignupParams: %w", err))
			}
			r.Body = io.NopCloser(bytes.NewReader(metadata))
			return a.MagicLink(w, r)
		}
		// otherwise confirmation email already contains 'magic link'
		if err := a.Signup(fakeResponse, r); err != nil {
			fmt.Println("MagicLink error (error signing up)", err)
			return err
		}

		return sendJSON(w, http.StatusOK, make(map[string]string))
	}
	fmt.Println("Got here arandomwordthatdoesntexist")

	if isPKCEFlow(flowType) {
		if _, err = generateFlowState(a.db, models.MagicLink.String(), models.MagicLink, params.CodeChallengeMethod, params.CodeChallenge, &user.ID); err != nil {
			fmt.Println("MagicLink error (error generating flow state)", err)
			return err
		}
	}

	err = db.Transaction(func(tx *storage.Connection) error {
		if terr := models.NewAuditLogEntry(r, tx, user, models.UserRecoveryRequestedAction, "", nil); terr != nil {
			fmt.Println("MagicLink error (error creating audit log entry)", terr)
			return terr
		}
		return a.sendMagicLink(r, tx, user, flowType)
	})
	if err != nil {
		return err
	}

	return sendJSON(w, http.StatusOK, make(map[string]string))
}

// responseStub only implement http responsewriter for ignoring
// incoming data from methods where it passed
type responseStub struct {
}

func (rw *responseStub) Header() http.Header {
	return http.Header{}
}

func (rw *responseStub) Write(data []byte) (int, error) {
	return 1, nil
}

func (rw *responseStub) WriteHeader(statusCode int) {
}

package model

import (
	"fmt"
)

type User struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Username string `json:"username"`
	Email    string `json:"email"`
	Role     string `json:"role"`
	IsValid  bool   `json:"is_valid"`
	IsActive bool   `json:"is_active"`
	OTPLevel int    `json:"otp_level"`

	// fallen's fork: check ssh host key -- add model field
	// https://github.com/jumpserver/jumpserver/blob/5e0babdba8adbcdbccdde85b5e66df242664f21a/apps/users/serializers/user.py#L132-L134
	IsSuperuser bool `json:"is_superuser"`
}

type MiniUser struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Username string `json:"username"`
}

func (u *User) String() string {
	return fmt.Sprintf("%s(%s)", u.Name, u.Username)
}

type UserKokoPreference struct {
	Basic KokoBasic `json:"basic"`
}
type KokoBasic struct {
	ThemeName string `json:"terminal_theme_name"`
}

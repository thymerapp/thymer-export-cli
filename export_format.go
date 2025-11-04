package main

import (
	"time"
)

type ExportKeyJsonV1 struct {
	Author             string `json:"author"` // email address
	EncWorkspaceKeyB64 string `json:"enc_workspace_key_b64"`
	KDFSalt            string `json:"kdf_salt"`
	KDFCostFactor      int    `json:"kdf_cost_factor"` // KDF algorithm is 'scrypt'
	IsEncrypted        bool   `json:"is_encrypted"`
}

type ExportMetaJson struct {
	Version string          `json:"version"`
	Date    time.Time       `json:"date"`
	Key     ExportKeyJsonV1 `json:"key"`
	// Other worksapce properties to restore
	CustomCSS string `json:"custom_css"`
}

type ExportOperationJsonV1 struct {
	GUID            string                 `json:"guid"`
	ByGUID          *string                `json:"by_guid"`
	Name            string                 `json:"name"`
	Sudo            bool                   `json:"sd"` // true: operation was created by server, false: created by client, recommend you don't change these in your operations.json
	Data            map[string]interface{} `json:"data"`
	Meta            string                 `json:"meta"`
	CreatedAt       int64                  `json:"created_at"`
	ServerCreatedAt int64                  `json:"server_created_at"`
}

type ExportBlobInfoJsonV1 struct {
	GUID          string     `json:"guid"`
	ByGUID        *string    `json:"by_guid"`
	ContentLength int64      `json:"content_length"`
	ContentType   string     `json:"content_type"`
	Status        int        `json:"status"`
	Meta          string     `json:"meta"`
	CreatedAt     time.Time  `json:"created_at"`
	UpdatedAt     time.Time  `json:"updated_at"`
	DeletedAt     *time.Time `json:"deleted_at"`
}

type ExportUserJsonV1 struct {
	GUID        string     `json:"guid"`
	Email       string     `json:"email"`
	Status      int        `json:"status"`
	Permissions int        `json:"permissions"`
	Meta        string     `json:"meta"`
	CreatedAt   time.Time  `json:"created_at"`
	UpdatedAt   time.Time  `json:"updated_at"`
	DeletedAt   *time.Time `json:"deleted_at"`
}

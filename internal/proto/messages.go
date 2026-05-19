package proto

type MessageType string

const (
	TypeOpen      MessageType = "open"
	TypeHeartbeat MessageType = "heartbeat"
)

const AuthLabel = "passage-auth-v1"

const PQAuthLabel = "passage-client-auth-v2"

const ExporterLength = 32

const MaxMessageSize = 64 * 1024

type ServerHello struct {
	Nonce      []byte `json:"nonce"`
	ServerTime int64  `json:"server_time"`
}

type ClientAuth struct {
	ClientID          string   `json:"client_id"`
	ClientTime        int64    `json:"client_time"`
	Signature         []byte   `json:"signature"`
	RequestedServices []string `json:"requested_services"`

	PQAlgorithm string `json:"pq_algorithm,omitempty"`
	PQSignature []byte `json:"pq_signature,omitempty"`
}

type Accepted struct {
	SessionID string `json:"session_id"`
}

type AuthFailed struct {
	Reason string `json:"reason"`
}

type Open struct {
	Type        MessageType `json:"type"`
	StreamID    uint64      `json:"stream_id"`
	ServiceName string      `json:"service_name"`
}

type Heartbeat struct {
	Type      MessageType `json:"type"`
	Timestamp int64       `json:"timestamp"`
}

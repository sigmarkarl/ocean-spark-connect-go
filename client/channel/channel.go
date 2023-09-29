//
// Licensed to the Apache Software Foundation (ASF) under one or more
// contributor license agreements.  See the NOTICE file distributed with
// this work for additional information regarding copyright ownership.
// The ASF licenses this file to You under the Apache License, Version 2.0
// (the "License"); you may not use this file except in compliance with
// the License.  You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package channel

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"

	"github.com/gorilla/websocket"

	"golang.org/x/oauth2"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/credentials/oauth"
)

// Reserved header parameters that must not be injected as variables.
var reservedParams = []string{"user_id", "token", "use_ssl"}

// The ChannelBuilder is used to parse the different parameters of the connection
// string according to the specification documented here:
//
//	https://github.com/apache/spark/blob/master/connector/connect/docs/client-connection-string.md
type ChannelBuilder struct {
	Scheme  string
	Host    string
	Port    int
	Path    string
	Query   string
	Token   string
	User    string
	Headers map[string]string
}

func (cb *ChannelBuilder) Build() (*grpc.ClientConn, error) {
	var opts []grpc.DialOption

	remote := fmt.Sprintf("%v:%v", cb.Host, cb.Port)
	opts = append(opts, grpc.WithAuthority(cb.Host))
	if cb.Scheme != "sc" {
		grpcSide, websocketSide := net.Pipe()
		u := url.URL{Scheme: cb.Scheme, Host: remote, Path: cb.Path, RawQuery: cb.Query}
		remote = ""
		header := http.Header{}
		header.Set("Authorization", "Bearer "+cb.Token)

		c, _, err := websocket.DefaultDialer.Dial(u.String(), header)
		if err != nil {
			log.Fatal("dial:", err)
		}

		opts = append(opts, grpc.WithTransportCredentials(insecure.NewCredentials()))
		opts = append(opts, grpc.WithContextDialer(func(ctx context.Context, s string) (net.Conn, error) {
			return grpcSide, nil
		}))

		done := make(chan struct{})
		data := make([]byte, 10*1024*1024)
		var wg sync.WaitGroup

		wg.Add(1)
		go func() {
			defer wg.Done()
			defer c.Close()
			defer close(done)
			for {
				mt, message, err := c.ReadMessage()
				if err != nil {
					log.Println("c.ReadMessage:", err)
					break
				}

				if mt != websocket.BinaryMessage {
					log.Println("mt != websocket.BinaryMessage")
					break
				}

				n, err := websocketSide.Write(message)
				if err != nil {
					log.Println("pipe.Write:", err)
					break
				}

				if len(message) != n {
					log.Printf("whooot! len(data) != n => %d != %d!\n", len(message), n)
					break
				}
			}
		}()

		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				n, err := websocketSide.Read(data)
				if err != nil {
					log.Println("pipe.Read:", err)
					break
				}

				err = c.WriteMessage(websocket.BinaryMessage, data[:n])
				if err != nil {
					log.Println("c.WriteMessage:", err)
					break
				}
			}
		}()
	} else if cb.Token == "" {
		opts = append(opts, grpc.WithTransportCredentials(insecure.NewCredentials()))
	} else {
		// Note: On the Windows platform, use of x509.SystemCertPool() requires
		// go version 1.18 or higher.
		systemRoots, err := x509.SystemCertPool()
		if err != nil {
			return nil, err
		}
		cred := credentials.NewTLS(&tls.Config{
			RootCAs: systemRoots,
		})
		opts = append(opts, grpc.WithTransportCredentials(cred))

		t := oauth2.Token{
			AccessToken: cb.Token,
			TokenType:   "bearer",
		}
		opts = append(opts, grpc.WithPerRPCCredentials(oauth.NewOauthAccess(&t)))
	}

	conn, err := grpc.Dial(remote, opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to remote %s: %w", remote, err)
	}
	return conn, nil
}

// Creates a new instance of the ChannelBuilder. This constructor effectively
// parses the connection string and extracts the relevant parameters directly.
func NewBuilder(connection string) (*ChannelBuilder, error) {

	u, err := url.Parse(connection)
	if err != nil {
		return nil, err
	}

	scheme := u.Scheme
	if scheme != "sc" && scheme != "ws" && scheme != "wss" {
		return nil, errors.New("URL schema must be set to `sc`.")
	}

	var port = 15002
	if scheme == "ws" {
		port = 80
	} else if scheme == "wss" {
		port = 443
	}
	var host = u.Host
	// Check if the host part of the URL contains a port and extract.
	if strings.Contains(u.Host, ":") {
		hostStr, portStr, err := net.SplitHostPort(u.Host)
		if err != nil {
			return nil, err
		}
		host = hostStr
		if len(portStr) != 0 {
			port, err = strconv.Atoi(portStr)
			if err != nil {
				return nil, err
			}
		}
	}

	// Validate that the URL path is empty or follows the right format.
	if scheme == "sc" && u.Path != "" && !strings.HasPrefix(u.Path, "/;") {
		return nil, fmt.Errorf("The URL path (%v) must be empty or have a proper parameter syntax.", u.Path)
	}

	var elements []string
	if scheme == "sc" {
		elements = strings.Split(u.Path, ";")
	} else {
		elements = strings.Split(u.RawQuery, ";")[1:]
		k := strings.Index(u.RawQuery, ";")
		if k > 0 {
			u.RawQuery = u.RawQuery[:k]
		}
	}

	cb := &ChannelBuilder{
		Scheme:  scheme,
		Host:    host,
		Port:    port,
		Path:    u.Path,
		Query:   u.RawQuery,
		Headers: map[string]string{},
	}

	for _, e := range elements {
		props := strings.Split(e, "=")
		if len(props) == 2 {
			if props[0] == "token" {
				cb.Token = props[1]
			} else if props[0] == "user_id" {
				cb.User = props[1]
			} else {
				cb.Headers[props[0]] = props[1]
			}
		}
	}
	return cb, nil
}

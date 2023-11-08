//go:build go1.18
// +build go1.18

package dns

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

var (
	clients = NewSharedClients()
)

func TestSharedClientSync(t *testing.T) {
	HandleFunc("miek.nl.", HelloServer)
	defer HandleRemove("miek.nl.")

	s, addrstr, _, err := RunLocalUDPServer(":0")
	if err != nil {
		t.Fatalf("unable to run test server: %v", err)
	}
	defer s.Shutdown()

	m := new(Msg)
	m.SetQuestion("miek.nl.", TypeSOA)

	c, closer := clients.GetSharedClient("client-key", new(Client), addrstr)
	defer closer()
	r, _, err := c.ExchangeShared(m)
	if err != nil {
		t.Fatalf("failed to exchange: %v", err)
	}
	if r == nil {
		t.Fatal("response is nil")
	}
	if r.Rcode != RcodeSuccess {
		t.Errorf("failed to get an valid answer\n%v", r)
	}
	// And now another ExchangeAsync on the same shared client
	r, _, err = c.ExchangeShared(m)
	if err != nil {
		t.Errorf("failed to exchange: %v", err)
	}
	if r == nil || r.Rcode != RcodeSuccess {
		t.Errorf("failed to get an valid answer\n%v", r)
	}

	// Now get the shared client again and make sure it is still the same client
	c2, closer2 := clients.GetSharedClient("client-key", new(Client), addrstr)
	defer closer2()

	if c2 != c {
		t.Fatal("client not really shared")
	}
	m.Id = uint16(42)
	r, _, err = c2.ExchangeShared(m)
	if err != nil {
		t.Errorf("failed to exchange: %v", err)
	}
	if r == nil || r.Rcode != RcodeSuccess {
		t.Errorf("failed to get an valid answer\n%v", r)
	}
}

func TestSharedClientConcurrentSync(t *testing.T) {
	HandleFunc("miek.nl.", HelloServer)
	defer HandleRemove("miek.nl.")

	s, addrstr, _, err := RunLocalUDPServer(":0")
	if err != nil {
		t.Fatalf("unable to run test server: %v", err)
	}
	defer s.Shutdown()

	conf := &Client{
		Timeout: 2 * time.Second,
	}

	errors := sync.Map{}
	var wg sync.WaitGroup
	f1 := func(id uint16) {
		defer wg.Done()

		m := new(Msg)
		m.SetQuestion("miek.nl.", TypeSOA)
		m.Id = id

		c, closer := clients.GetSharedClient("concurrent-client", conf, addrstr)
		defer closer()
		r, _, err := c.ExchangeShared(m)
		if err != nil {
			errors.Store(id, fmt.Errorf("failed to exchange: %v", err))
			return
		}
		if r == nil {
			errors.Store(id, fmt.Errorf("response is nil"))
			return
		}
		if r.Id != id {
			errors.Store(id, fmt.Errorf("incorrect id (%d != %d)", r.Id, id))
		}
		if r.Rcode != RcodeSuccess {
			errors.Store(id, fmt.Errorf("failed to get an valid answer\n%v", r))
		}
	}

	for id := uint16(1); id <= 250; id++ {
		wg.Add(1)
		go f1(id)
	}
	wg.Wait()

	errors.Range(func(key, value any) bool {
		t.Errorf("Id: %v, error: %v", key, value)
		return true
	})
}

func TestSharedClientLocalAddress(t *testing.T) {
	HandleFunc("miek.nl.", HelloServerEchoAddrPort)
	defer HandleRemove("miek.nl.")

	s, addrstr, _, err := RunLocalUDPServer(":0")
	if err != nil {
		t.Fatalf("unable to run test server: %v", err)
	}
	defer s.Shutdown()

	m := new(Msg)
	m.SetQuestion("miek.nl.", TypeSOA)

	c, closer := clients.GetSharedClient("", new(Client), addrstr)
	defer closer()

	laddr := net.UDPAddr{IP: net.ParseIP("0.0.0.0"), Port: 12345, Zone: ""}
	c.Dialer = &net.Dialer{LocalAddr: &laddr}

	r, _, err := c.ExchangeShared(m)
	if err != nil {
		t.Fatalf("failed to exchange: %v", err)
	}
	if r == nil {
		t.Fatalf("No response")
	}
	if r.Rcode != RcodeSuccess {
		t.Errorf("failed to get an valid answer\n%v", r)
	}
	if len(r.Extra) != 1 {
		t.Fatalf("failed to get additional answers\n%v", r)
	}
	txt := r.Extra[0].(*TXT)
	if txt == nil {
		t.Errorf("invalid TXT response\n%v", txt)
	}
	if len(txt.Txt) != 1 || !strings.Contains(txt.Txt[0], ":12345") {
		t.Errorf("invalid TXT response\n%v", txt.Txt)
	}
}

func TestSharedClientTLSSyncV4(t *testing.T) {
	HandleFunc("miek.nl.", HelloServer)
	defer HandleRemove("miek.nl.")

	cert, err := tls.X509KeyPair(CertPEMBlock, KeyPEMBlock)
	if err != nil {
		t.Fatalf("unable to build certificate: %v", err)
	}

	config := tls.Config{
		Certificates: []tls.Certificate{cert},
	}

	s, addrstr, _, err := RunLocalTLSServer(":0", &config)
	if err != nil {
		t.Fatalf("unable to run test server: %v", err)
	}
	defer s.Shutdown()

	m := new(Msg)
	m.SetQuestion("miek.nl.", TypeSOA)

	c, closer := clients.GetSharedClient("", new(Client), addrstr)
	defer closer()

	// test tcp-tls
	c.Net = "tcp-tls"
	c.TLSConfig = &tls.Config{
		InsecureSkipVerify: true,
	}

	r, _, err := c.ExchangeShared(m)
	if err != nil {
		t.Fatalf("failed to exchange: %v", err)
	}
	if r == nil {
		t.Fatal("response is nil")
	}
	if r.Rcode != RcodeSuccess {
		t.Errorf("failed to get an valid answer\n%v", r)
	}

	// test tcp4-tls
	c.Net = "tcp4-tls"
	c.TLSConfig = &tls.Config{
		InsecureSkipVerify: true,
	}

	r, _, err = c.ExchangeShared(m)
	if err != nil {
		t.Fatalf("failed to exchange: %v", err)
	}
	if r == nil {
		t.Fatal("response is nil")
	}
	if r.Rcode != RcodeSuccess {
		t.Errorf("failed to get an valid answer\n%v", r)
	}
}

func TestSharedClientSyncBadID(t *testing.T) {
	HandleFunc("miek.nl.", HelloServerBadID)
	defer HandleRemove("miek.nl.")

	s, addrstr, _, err := RunLocalUDPServer(":0")
	if err != nil {
		t.Fatalf("unable to run test server: %v", err)
	}
	defer s.Shutdown()

	m := new(Msg)
	m.SetQuestion("miek.nl.", TypeSOA)

	// Test with client.Exchange, the plain Exchange function is just a wrapper, so
	// we don't need to test that separately.
	conf := &Client{
		Timeout: 10 * time.Millisecond,
	}

	_, _, closer, err := clients.Exchange("", conf, m, addrstr)
	defer closer()

	if err == nil || !isNetworkTimeout(err) {
		t.Errorf("query did not time out")
	}
}

func TestSharedClientSyncBadThenGoodID(t *testing.T) {
	HandleFunc("miek.nl.", HelloServerBadThenGoodID)
	defer HandleRemove("miek.nl.")

	s, addrstr, _, err := RunLocalUDPServer(":0")
	if err != nil {
		t.Fatalf("unable to run test server: %v", err)
	}
	defer s.Shutdown()

	m := new(Msg)
	m.SetQuestion("miek.nl.", TypeSOA)

	r, _, closer, err := clients.ExchangeContext(context.TODO(), "", new(Client), m, addrstr)
	defer closer()

	if err != nil {
		t.Fatalf("failed to exchange: %v", err)
	}
	if r == nil {
		t.Fatalf("No response")
	}
	if r.Id != m.Id {
		t.Errorf("failed to get response with expected Id")
	}
}

func TestSharedClientSyncTCPBadID(t *testing.T) {
	HandleFunc("miek.nl.", HelloServerBadID)
	defer HandleRemove("miek.nl.")

	s, addrstr, _, err := RunLocalTCPServer(":0")
	if err != nil {
		t.Fatalf("unable to run test server: %v", err)
	}
	defer s.Shutdown()

	m := new(Msg)
	m.SetQuestion("miek.nl.", TypeSOA)

	c, closer := clients.GetSharedClient("", new(Client), addrstr)
	defer closer()

	c.Net = "tcp"
	c.Timeout = 10 * time.Millisecond

	// ExchangeShared does not pass through bad IDs, they will be filtered out just like
	// for UDP and the request should time out
	if _, _, err := c.ExchangeShared(m); err == nil || !isNetworkTimeout(err) {
		t.Errorf("query did not time out")
	}
}

func TestSharedClientEDNS0(t *testing.T) {
	HandleFunc("miek.nl.", HelloServer)
	defer HandleRemove("miek.nl.")

	s, addrstr, _, err := RunLocalUDPServer(":0")
	if err != nil {
		t.Fatalf("unable to run test server: %v", err)
	}
	defer s.Shutdown()

	m := new(Msg)
	m.SetQuestion("miek.nl.", TypeDNSKEY)

	m.SetEdns0(2048, true)

	c, closer := clients.GetSharedClient("", new(Client), addrstr)
	defer closer()

	r, _, err := c.ExchangeShared(m)
	if err != nil {
		t.Fatalf("failed to exchange: %v", err)
	}

	if r != nil && r.Rcode != RcodeSuccess {
		t.Errorf("failed to get a valid answer\n%v", r)
	}
}

// Validates the transmission and parsing of local EDNS0 options.
func TestSharedClientEDNS0Local(t *testing.T) {
	optStr1 := "1979:0x0707"
	optStr2 := strconv.Itoa(EDNS0LOCALSTART) + ":0x0601"

	handler := func(w ResponseWriter, req *Msg) {
		m := new(Msg)
		m.SetReply(req)

		m.Extra = make([]RR, 1, 2)
		m.Extra[0] = &TXT{Hdr: RR_Header{Name: m.Question[0].Name, Rrtype: TypeTXT, Class: ClassINET, Ttl: 0}, Txt: []string{"Hello local edns"}}

		// If the local options are what we expect, then reflect them back.
		ec1 := req.Extra[0].(*OPT).Option[0].(*EDNS0_LOCAL).String()
		ec2 := req.Extra[0].(*OPT).Option[1].(*EDNS0_LOCAL).String()
		if ec1 == optStr1 && ec2 == optStr2 {
			m.Extra = append(m.Extra, req.Extra[0])
		}

		w.WriteMsg(m)
	}

	HandleFunc("miek.nl.", handler)
	defer HandleRemove("miek.nl.")

	s, addrstr, _, err := RunLocalUDPServer(":0")
	if err != nil {
		t.Fatalf("unable to run test server: %s", err)
	}
	defer s.Shutdown()

	m := new(Msg)
	m.SetQuestion("miek.nl.", TypeTXT)

	// Add two local edns options to the query.
	ec1 := &EDNS0_LOCAL{Code: 1979, Data: []byte{7, 7}}
	ec2 := &EDNS0_LOCAL{Code: EDNS0LOCALSTART, Data: []byte{6, 1}}
	o := &OPT{Hdr: RR_Header{Name: ".", Rrtype: TypeOPT}, Option: []EDNS0{ec1, ec2}}
	m.Extra = append(m.Extra, o)

	c, closer := clients.GetSharedClient("", new(Client), addrstr)
	defer closer()

	r, _, err := c.ExchangeShared(m)
	if err != nil {
		t.Fatalf("failed to exchange: %s", err)
	}

	if r == nil {
		t.Fatal("response is nil")
	}
	if r.Rcode != RcodeSuccess {
		t.Fatal("failed to get a valid answer")
	}

	txt := r.Extra[0].(*TXT).Txt[0]
	if txt != "Hello local edns" {
		t.Error("Unexpected result for miek.nl", txt, "!= Hello local edns")
	}

	// Validate the local options in the reply.
	got := r.Extra[1].(*OPT).Option[0].(*EDNS0_LOCAL).String()
	if got != optStr1 {
		t.Errorf("failed to get local edns0 answer; got %s, expected %s", got, optStr1)
	}

	got = r.Extra[1].(*OPT).Option[1].(*EDNS0_LOCAL).String()
	if got != optStr2 {
		t.Errorf("failed to get local edns0 answer; got %s, expected %s", got, optStr2)
	}
}

func TestSharedTimeout(t *testing.T) {
	// Set up a dummy UDP server that won't respond
	addr, err := net.ResolveUDPAddr("udp", ":0")
	if err != nil {
		t.Fatalf("unable to resolve local udp address: %v", err)
	}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		t.Fatalf("unable to run test server: %v", err)
	}
	defer conn.Close()
	addrstr := conn.LocalAddr().String()

	// Message to send
	m := new(Msg)
	m.SetQuestion("miek.nl.", TypeTXT)

	runTest := func(name string, exchange func(m *Msg, addr string, timeout time.Duration) (*Msg, time.Duration, error)) {
		t.Run(name, func(t *testing.T) {
			start := time.Now()

			timeout := time.Millisecond
			// Need some more slack for the goroutines to close
			allowable := timeout + 50*time.Millisecond

			_, _, err := exchange(m, addrstr, timeout)
			if err == nil {
				t.Errorf("no timeout using Client.%s", name)
			}

			length := time.Since(start)
			if length > allowable {
				t.Errorf("exchange took longer %v than specified Timeout %v", length, allowable)
			}
		})
	}
	runTest("ExchangeShared", func(m *Msg, addr string, timeout time.Duration) (*Msg, time.Duration, error) {
		c, closer := clients.GetSharedClient("", &Client{Timeout: timeout}, addrstr)
		defer closer()

		return c.ExchangeShared(m)
	})
	runTest("ExchangeSharedContext", func(m *Msg, addr string, timeout time.Duration) (*Msg, time.Duration, error) {
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()

		c, closer := clients.GetSharedClient("", new(Client), addrstr)
		defer closer()

		return c.ExchangeSharedContext(ctx, m)
	})
}

// Check that responses from deduplicated requests aren't shared between callers
func TestSharedConcurrentExchanges(t *testing.T) {
	cases := make([]*Msg, 2)
	cases[0] = new(Msg)
	cases[1] = new(Msg)
	cases[1].Truncated = true

	for _, m := range cases {
		mm := m // redeclare m so as not to trip the race detector
		handler := func(w ResponseWriter, req *Msg) {
			r := mm.Copy()
			r.SetReply(req)

			w.WriteMsg(r)
		}

		HandleFunc("miek.nl.", handler)
		defer HandleRemove("miek.nl.")

		s, addrstr, _, err := RunLocalUDPServer(":0")
		if err != nil {
			t.Fatalf("unable to run test server: %s", err)
		}
		defer s.Shutdown()

		m := new(Msg)
		m.SetQuestion("miek.nl.", TypeSRV)

		c, closer := clients.GetSharedClient("", &Client{SingleInflight: true}, addrstr)
		defer closer()

		// Force this client to always return the same request,
		// even though we're querying sequentially. Running the
		// Exchange calls below concurrently can fail due to
		// goroutine scheduling, but this simulates the same
		// outcome.
		c.group.dontDeleteForTesting = true

		r := make([]*Msg, 2)
		for i := range r {
			r[i], _, err = c.ExchangeShared(m.Copy())
			if err != nil {
				t.Fatalf("failed to exchange: %s", err)
			}
			if r[i] == nil {
				t.Fatalf("response %d is nil", i)
			}
		}

		if r[0] == r[1] {
			t.Errorf("got same response, expected non-shared responses")
		}
	}
}

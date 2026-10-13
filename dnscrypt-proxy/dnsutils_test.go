package main

import (
	"testing"
	"time"

	"codeberg.org/miekg/dns"
)

func TestGetMinTTL(t *testing.T) {
	const (
		minTTL         = 900
		maxTTL         = 3600
		cacheNegMinTTL = 30
		cacheNegMaxTTL = 300
	)
	ns := func(ttl uint32) dns.RR {
		return &dns.NS{Hdr: dns.Header{Name: "facebook.com.", Class: dns.ClassINET, TTL: ttl}}
	}
	soa := func(ttl uint32) dns.RR {
		return &dns.SOA{Hdr: dns.Header{Name: "facebook.com.", Class: dns.ClassINET, TTL: ttl}}
	}
	a := func(ttl uint32) dns.RR {
		return &dns.A{Hdr: dns.Header{Name: "www.facebook.com.", Class: dns.ClassINET, TTL: ttl}}
	}
	noError := func(answer, authority []dns.RR) *dns.Msg {
		msg := &dns.Msg{}
		msg.Rcode = dns.RcodeSuccess
		msg.Answer = answer
		msg.Ns = authority
		return msg
	}
	nxDomain := func(authority []dns.RR) *dns.Msg {
		msg := noError(nil, authority)
		msg.Rcode = dns.RcodeNameError
		return msg
	}
	servFail := noError(nil, []dns.RR{ns(1800)})
	servFail.Rcode = dns.RcodeServerFailure

	tests := []struct {
		name string
		msg  *dns.Msg
		want time.Duration
	}{
		{
			name: "noerror_ns_only_authority",
			msg:  noError(nil, []dns.RR{ns(1800)}),
			want: 30 * time.Second,
		},
		{
			name: "nxdomain_ns_only_authority",
			msg:  nxDomain([]dns.RR{ns(1800)}),
			want: 30 * time.Second,
		},
		{
			name: "noerror_empty_authority",
			msg:  noError(nil, nil),
			want: 30 * time.Second,
		},
		{
			name: "noerror_soa_authority",
			msg:  noError(nil, []dns.RR{soa(1800)}),
			want: 1800 * time.Second,
		},
		{
			name: "noerror_soa_authority_below_min",
			msg:  noError(nil, []dns.RR{soa(60)}),
			want: 900 * time.Second,
		},
		{
			name: "noerror_soa_authority_above_max",
			msg:  noError(nil, []dns.RR{soa(7200)}),
			want: 3600 * time.Second,
		},
		{
			name: "noerror_ns_then_soa_authority",
			msg:  noError(nil, []dns.RR{ns(2400), soa(1800)}),
			want: 1800 * time.Second,
		},
		{
			name: "noerror_soa_then_lower_ns_authority",
			msg:  noError(nil, []dns.RR{soa(1800), ns(1200)}),
			want: 1200 * time.Second,
		},
		{
			name: "nxdomain_soa_authority",
			msg:  nxDomain([]dns.RR{soa(120)}),
			want: 120 * time.Second,
		},
		{
			name: "nxdomain_soa_authority_below_neg_min",
			msg:  nxDomain([]dns.RR{soa(5)}),
			want: 30 * time.Second,
		},
		{
			name: "nxdomain_soa_authority_above_neg_max",
			msg:  nxDomain([]dns.RR{soa(1800)}),
			want: 300 * time.Second,
		},
		{
			name: "noerror_smallest_a_answer",
			msg:  noError([]dns.RR{a(1800), a(1200)}, nil),
			want: 1200 * time.Second,
		},
		{
			name: "noerror_a_answer_below_min",
			msg:  noError([]dns.RR{a(60)}, nil),
			want: 900 * time.Second,
		},
		{
			name: "noerror_a_answer_above_max",
			msg:  noError([]dns.RR{a(7200)}, nil),
			want: 3600 * time.Second,
		},
		{
			name: "noerror_a_answer_with_ns_only_authority",
			msg:  noError([]dns.RR{a(1200)}, []dns.RR{ns(5)}),
			want: 1200 * time.Second,
		},
		{
			name: "servfail",
			msg:  servFail,
			want: 30 * time.Second,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := getMinTTL(tt.msg, minTTL, maxTTL, cacheNegMinTTL, cacheNegMaxTTL)
			if got != tt.want {
				t.Errorf("getMinTTL() = %v, want %v", got, tt.want)
			}
		})
	}
}

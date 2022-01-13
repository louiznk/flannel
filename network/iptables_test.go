// Copyright 2015 flannel authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//go:build !windows
// +build !windows

package network

import (
	"fmt"
	"net"
	"reflect"
	"strings"
	"testing"

	"github.com/flannel-io/flannel/pkg/ip"
	"github.com/flannel-io/flannel/subnet"
)

func lease() *subnet.Lease {
	_, ipv6Net, _ := net.ParseCIDR("fc00::/48")
	_, net, _ := net.ParseCIDR("192.168.0.0/16")
	return &subnet.Lease{
		Subnet:     ip.FromIPNet(net),
		IPv6Subnet: ip.FromIP6Net(ipv6Net),
	}
}

type MockIPTables struct {
	rules    []IPTablesRule
	t        *testing.T
	failures map[string]*MockIPTablesError
}

type MockIPTablesRestore struct {
	t     *testing.T
	rules []IPTablesRestoreRules
}

type MockIPTablesError struct {
	notExist bool
}

func (mock *MockIPTablesError) IsNotExist() bool {
	return mock.notExist
}

func (mock *MockIPTablesError) Error() string {
	return fmt.Sprintf("IsNotExist: %v", !mock.notExist)
}

func (mock *MockIPTables) failDelete(table string, chain string, rulespec []string, notExist bool) {

	if mock.failures == nil {
		mock.failures = make(map[string]*MockIPTablesError)
	}
	key := table + chain + strings.Join(rulespec, "")
	mock.failures[key] = &MockIPTablesError{
		notExist: notExist,
	}
}

func (mock *MockIPTablesRestore) ApplyFully(rules IPTablesRestoreRules) error {
	mock.rules = []IPTablesRestoreRules{rules}
	return nil
}

func (mock *MockIPTablesRestore) ApplyWithoutFlush(rules IPTablesRestoreRules) error {
	mock.rules = append(mock.rules, rules)
	return nil
}

func (mock *MockIPTables) ruleIndex(table string, chain string, rulespec []string) int {
	for i, rule := range mock.rules {
		if rule.table == table && rule.chain == chain && reflect.DeepEqual(rule.rulespec, rulespec) {
			return i
		}
	}
	return -1
}

func (mock *MockIPTables) Delete(table string, chain string, rulespec ...string) error {
	var ruleIndex = mock.ruleIndex(table, chain, rulespec)
	key := table + chain + strings.Join(rulespec, "")
	reason := mock.failures[key]
	if reason != nil {
		return reason
	}

	if ruleIndex != -1 {
		mock.rules = append(mock.rules[:ruleIndex], mock.rules[ruleIndex+1:]...)
	}
	return nil
}

func (mock *MockIPTables) Exists(table string, chain string, rulespec ...string) (bool, error) {
	var ruleIndex = mock.ruleIndex(table, chain, rulespec)
	if ruleIndex != -1 {
		return true, nil
	}
	return false, nil
}

func (mock *MockIPTables) AppendUnique(table string, chain string, rulespec ...string) error {
	var ruleIndex = mock.ruleIndex(table, chain, rulespec)
	if ruleIndex == -1 {
		mock.rules = append(mock.rules, IPTablesRule{table: table, chain: chain, rulespec: rulespec})
	}
	return nil
}

func TestDeleteRules(t *testing.T) {
	ipt := &MockIPTables{t: t}
	iptr := &MockIPTablesRestore{t: t}
	baseRules := MasqRules(ip.IP4Net{}, lease())
	expectedRules := expectedTearDownIPTablesRestoreRules(baseRules)

	ipTablesBootstrap(ipt, iptr, baseRules)
	setupIPTables(ipt, baseRules)
	if len(ipt.rules) != 4 {
		t.Errorf("Should be 4 masqRules, there are actually %d: %#v", len(ipt.rules), ipt.rules)
	}

	iptr.rules = []IPTablesRestoreRules{}
	teardownIPTables(ipt, iptr, baseRules)
	if !reflect.DeepEqual(expectedRules, iptr.rules) {
		t.Errorf("Incorrect restores rules, Expected: %#v, Actual: %#v", expectedRules, iptr.rules)
	}

}

func TestDeleteMoreRules(t *testing.T) {
	ipt := &MockIPTables{}
	iptr := &MockIPTablesRestore{}

	baseRules := []IPTablesRule{
		{"filter", "INPUT", []string{"-s", "127.0.0.1", "-d", "127.0.0.1", "-j", "RETURN"}},
		{"filter", "INPUT", []string{"-s", "127.0.0.1", "!", "-d", "224.0.0.0/4", "-j", "MASQUERADE", "--random-fully"}},
		{"nat", "POSTROUTING", []string{"-s", "127.0.0.1", "-d", "127.0.0.1", "-j", "RETURN"}},
		{"nat", "POSTROUTING", []string{"-s", "127.0.0.1", "!", "-d", "224.0.0.0/4", "-j", "MASQUERADE", "--random-fully"}},
	}

	expectedRules := IPTablesRestoreRules{
		"filter": []IPTablesRestoreRuleSpec{
			IPTablesRestoreRuleSpec{"-D", "INPUT", "-s", "127.0.0.1", "-d", "127.0.0.1", "-j", "RETURN"},
			IPTablesRestoreRuleSpec{"-D", "INPUT", "-s", "127.0.0.1", "!", "-d", "224.0.0.0/4", "-j", "MASQUERADE", "--random-fully"},
		},
		"nat": []IPTablesRestoreRuleSpec{
			IPTablesRestoreRuleSpec{"-D", "POSTROUTING", "-s", "127.0.0.1", "-d", "127.0.0.1", "-j", "RETURN"},
			IPTablesRestoreRuleSpec{"-D", "POSTROUTING", "-s", "127.0.0.1", "!", "-d", "224.0.0.0/4", "-j", "MASQUERADE", "--random-fully"},
		},
	}

	ipTablesBootstrap(ipt, iptr, baseRules)
	setupIPTables(ipt, baseRules)
	if len(ipt.rules) != 4 {
		t.Errorf("Should be 4 masqRules, there are actually %d: %#v", len(ipt.rules), ipt.rules)
	}

	iptr.rules = []IPTablesRestoreRules{}
	err := teardownIPTables(ipt, iptr, baseRules)
	if err != nil {
		return
	}
	if !reflect.DeepEqual(iptr.rules, []IPTablesRestoreRules{expectedRules}) {
		t.Errorf("Incorrect restores rules, Expected: %#v, Actual: %#v", expectedRules, iptr.rules)
	}
}

func TestBootstrapRules(t *testing.T) {
	iptr := &MockIPTablesRestore{}
	ipt := &MockIPTables{}

	baseRules := []IPTablesRule{
		{"filter", "INPUT", []string{"-s", "127.0.0.1", "-d", "127.0.0.1", "-j", "RETURN"}},
		{"filter", "INPUT", []string{"-s", "127.0.0.1", "!", "-d", "224.0.0.0/4", "-j", "MASQUERADE", "--random-fully"}},
		{"nat", "POSTROUTING", []string{"-s", "127.0.0.1", "-d", "127.0.0.1", "-j", "RETURN"}},
		{"nat", "POSTROUTING", []string{"-s", "127.0.0.1", "!", "-d", "224.0.0.0/4", "-j", "MASQUERADE", "--random-fully"}},
	}

	ipTablesBootstrap(ipt, iptr, baseRules)
	// Ensure iptable mock has rules too
	setupIPTables(ipt, baseRules)

	expectedRules := IPTablesRestoreRules{
		"filter": []IPTablesRestoreRuleSpec{
			IPTablesRestoreRuleSpec{"-A", "INPUT", "-s", "127.0.0.1", "-d", "127.0.0.1", "-j", "RETURN"},
			IPTablesRestoreRuleSpec{"-A", "INPUT", "-s", "127.0.0.1", "!", "-d", "224.0.0.0/4", "-j", "MASQUERADE", "--random-fully"},
		},
		"nat": []IPTablesRestoreRuleSpec{
			IPTablesRestoreRuleSpec{"-A", "POSTROUTING", "-s", "127.0.0.1", "-d", "127.0.0.1", "-j", "RETURN"},
			IPTablesRestoreRuleSpec{"-A", "POSTROUTING", "-s", "127.0.0.1", "!", "-d", "224.0.0.0/4", "-j", "MASQUERADE", "--random-fully"},
		},
	}

	if !reflect.DeepEqual(iptr.rules, []IPTablesRestoreRules{expectedRules}) {
		t.Errorf("iptables masqRules after ensureIPTables are incorrected. Expected: %#v, Actual: %#v", expectedRules, iptr.rules)
	}

	iptr.rules = []IPTablesRestoreRules{}

	expectedRules = IPTablesRestoreRules{
		"filter": []IPTablesRestoreRuleSpec{
			IPTablesRestoreRuleSpec{"-D", "INPUT", "-s", "127.0.0.1", "-d", "127.0.0.1", "-j", "RETURN"},
			IPTablesRestoreRuleSpec{"-A", "INPUT", "-s", "127.0.0.1", "-d", "127.0.0.1", "-j", "RETURN"},
			IPTablesRestoreRuleSpec{"-D", "INPUT", "-s", "127.0.0.1", "!", "-d", "224.0.0.0/4", "-j", "MASQUERADE", "--random-fully"},
			IPTablesRestoreRuleSpec{"-A", "INPUT", "-s", "127.0.0.1", "!", "-d", "224.0.0.0/4", "-j", "MASQUERADE", "--random-fully"},
		},
		"nat": []IPTablesRestoreRuleSpec{
			IPTablesRestoreRuleSpec{"-D", "POSTROUTING", "-s", "127.0.0.1", "-d", "127.0.0.1", "-j", "RETURN"},
			IPTablesRestoreRuleSpec{"-A", "POSTROUTING", "-s", "127.0.0.1", "-d", "127.0.0.1", "-j", "RETURN"},
			IPTablesRestoreRuleSpec{"-D", "POSTROUTING", "-s", "127.0.0.1", "!", "-d", "224.0.0.0/4", "-j", "MASQUERADE", "--random-fully"},
			IPTablesRestoreRuleSpec{"-A", "POSTROUTING", "-s", "127.0.0.1", "!", "-d", "224.0.0.0/4", "-j", "MASQUERADE", "--random-fully"},
		},
	}
	// Re-run ensure has new operations
	ipTablesBootstrap(ipt, iptr, baseRules)
	if !reflect.DeepEqual(iptr.rules, []IPTablesRestoreRules{expectedRules}) {
		t.Errorf("iptables masqRules after ensureIPTables are incorrected. Expected: %#v, Actual: %#v", expectedRules, iptr.rules)
	}
}

func TestDeleteIP6Rules(t *testing.T) {
	ipt := &MockIPTables{t: t}
	iptr := &MockIPTablesRestore{t: t}

	baseRules := MasqIP6Rules(ip.IP6Net{}, lease())
	expectedRules := expectedTearDownIPTablesRestoreRules(baseRules)

	ipTablesBootstrap(ipt, iptr, baseRules)
	setupIPTables(ipt, baseRules)

	if len(ipt.rules) != 4 {
		t.Errorf("Should be 4 masqRules, there are actually %d: %#v", len(ipt.rules), ipt.rules)
	}

	iptr.rules = []IPTablesRestoreRules{}
	teardownIPTables(ipt, iptr, baseRules)
	if !reflect.DeepEqual(expectedRules, iptr.rules) {
		t.Errorf("Incorrect restores rules, Expected: %#v, Actual: %#v", expectedRules, iptr.rules)
	}
}

func TestEnsureRules(t *testing.T) {
	iptr := &MockIPTablesRestore{}
	ipt := &MockIPTables{}

	// Ensure iptable mock has other rules
	otherRules := []IPTablesRule{
		{"nat", "POSTROUTING", []string{"-A", "POSTROUTING", "-j", "KUBE-POSTROUTING"}},
	}
	setupIPTables(ipt, otherRules)

	baseRules := []IPTablesRule{
		{"nat", "POSTROUTING", []string{"-s", "127.0.0.1", "-d", "127.0.0.1", "-j", "RETURN"}},
		{"nat", "POSTROUTING", []string{"-s", "127.0.0.1", "!", "-d", "224.0.0.0/4", "-j", "MASQUERADE", "--random-fully"}},
	}

	ensureIPTables(ipt, iptr, baseRules)
	// Ensure iptable mock has rules too
	setupIPTables(ipt, baseRules)

	expectedRules := IPTablesRestoreRules{
		"nat": []IPTablesRestoreRuleSpec{
			IPTablesRestoreRuleSpec{"-A", "POSTROUTING", "-s", "127.0.0.1", "-d", "127.0.0.1", "-j", "RETURN"},
			IPTablesRestoreRuleSpec{"-A", "POSTROUTING", "-s", "127.0.0.1", "!", "-d", "224.0.0.0/4", "-j", "MASQUERADE", "--random-fully"},
		},
	}

	if !reflect.DeepEqual(iptr.rules, []IPTablesRestoreRules{expectedRules}) {
		t.Errorf("iptables masqRules after ensureIPTables are incorrected. Expected: %#v, Actual: %#v", expectedRules, iptr.rules)
	}

	iptr.rules = []IPTablesRestoreRules{}
	// Re-run ensure no new operations
	ensureIPTables(ipt, iptr, baseRules)
	if len(iptr.rules) > 0 {
		t.Errorf("iptables masqRules after ensureIPTables are incorrected. Expected: %#v, Actual: %#v", expectedRules, iptr.rules)
	}
}

func setupIPTables(ipt IPTables, rules []IPTablesRule) error {
	for _, rule := range rules {
		err := ipt.AppendUnique(rule.table, rule.chain, rule.rulespec...)
		if err != nil {
			return fmt.Errorf("failed to insert IPTables rule: %v", err)
		}
	}

	return nil
}

func expectedTearDownIPTablesRestoreRules(rules []IPTablesRule) []IPTablesRestoreRules {
	tablesRules := IPTablesRestoreRules{}
	for _, rule := range rules {
		if _, ok := tablesRules[rule.table]; !ok {
			tablesRules[rule.table] = []IPTablesRestoreRuleSpec{}
		}
		tablesRules[rule.table] = append(tablesRules[rule.table], append(IPTablesRestoreRuleSpec{"-D", rule.chain}, rule.rulespec...))
	}

	return []IPTablesRestoreRules{tablesRules}
}

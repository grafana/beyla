// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon // import "go.opentelemetry.io/obi/pkg/ebpf/common"

import (
	"time"

	"github.com/hashicorp/golang-lru/v2/expirable"
	"github.com/hashicorp/golang-lru/v2/simplelru"

	"go.opentelemetry.io/obi/pkg/internal/ebpf/kafkaparser"
)

const (
	// maxGroupsPerProcess bounds the memberships kept for one process.
	maxGroupsPerProcess = 64
	// maxMembersPerGroup bounds the members of one group kept for one process.
	maxMembersPerGroup = 64
	// maxTopicsPerMember bounds the subscription kept for one member.
	maxTopicsPerMember = 1024
	// maxTopicsPerProcess bounds the topics kept across all members of a process, since
	// every OffsetCommit may name new ones and the LRU limits processes, not their weight.
	// A topic that did not fit reads as not subscribed: when two groups of the process
	// consume it, the Fetch is attributed to the other group instead of to neither.
	maxTopicsPerProcess = 4096
)

// KafkaProcess identifies the instrumented process a Kafka request was captured from.
// Fetch requests carry no consumer group, and the group-coordination requests that do
// go to the group coordinator, usually not the leader of the fetched partitions: on a
// dedicated connection (Java, kafka-python) or on that broker's shared connection
// (librdkafka). Either way the process is the only key shared by both.
type KafkaProcess struct {
	Ns  uint32
	Pid uint32
}

// kafkaMember is one member of a group living in a process. A process may host several
// members of the same group, each with its own subscription: every Kafka Streams thread
// is a consumer of the application's group, and nothing stops an application from
// opening two consumers with the same group.id.
type kafkaMember struct {
	// topics is the member's subscription as far as it was observed: replaced by a fully
	// captured JoinGroup subscription, extended by the topics other requests name.
	topics map[string]struct{}
	// expires is when the member is forgotten unless another membership request renews
	// it. Kept per member: a recycled pid heartbeating for its own group must not keep
	// the previous process' memberships alive.
	expires time.Time
}

// addTopics adds topics to the subscription, at most budget new ones (the process' share
// left, see maxTopicsPerProcess) and maxTopicsPerMember in total.
func (m *kafkaMember) addTopics(topics []*kafkaparser.GroupTopic, kafkaTopicUUIDToName *simplelru.LRU[kafkaparser.UUID, string], budget int) {
	for _, topic := range topics {
		name := resolveTopicName(topic.Name, topic.UUID, kafkaTopicUUIDToName)
		if name == "" {
			continue
		}
		if _, found := m.topics[name]; found {
			continue
		}
		if budget <= 0 || len(m.topics) >= maxTopicsPerMember {
			continue
		}
		m.topics[name] = struct{}{}
		budget--
	}
}

// kafkaMembership is what is known about one group a process is a member of.
type kafkaMembership struct {
	// foreign marks a group whose JoinGroup or SyncGroup named a protocol other than
	// "consumer" (Kafka Connect, Schema Registry): it coordinates through the same APIs
	// but is no consumer group. A Heartbeat seen before that JoinGroup leaves it unset.
	foreign bool
	// members are the group's members living in the process, by member id. The group's
	// subscription is the union of theirs and of the pending ones.
	members map[string]*kafkaMember
	// pending are the members the coordinator has not named yet, by connection: a first
	// JoinGroup carries no member id, and the id comes back only in the response. A broker
	// since 2.2 answers MEMBER_ID_REQUIRED and the member repeats the JoinGroup with its id
	// (KIP-394); an older one accepts it, and the id first shows up in the SyncGroup or
	// Heartbeat; a KIP-848 member before KIP-1082 learns it from its first heartbeat's
	// response. Each consumer talks to the coordinator on a connection of its own, so the
	// first named request on a pending member's connection is that member. A pending
	// member nobody names expires like any other.
	pending map[BpfConnectionInfoT]*kafkaMember
}

func newKafkaMember() *kafkaMember {
	return &kafkaMember{topics: map[string]struct{}{}}
}

// size is the number of members, named and pending, kept for the group.
func (g *kafkaMembership) size() int {
	return len(g.members) + len(g.pending)
}

func (g *kafkaMembership) member(id string, conn BpfConnectionInfoT) *kafkaMember {
	if id == "" {
		return g.pendingMember(conn)
	}
	if m, found := g.members[id]; found {
		return m
	}
	if m, found := g.pending[conn]; found {
		delete(g.pending, conn)
		g.members[id] = m
		return m
	}
	if g.size() >= maxMembersPerGroup {
		return nil
	}
	m := newKafkaMember()
	g.members[id] = m
	return m
}

func (g *kafkaMembership) pendingMember(conn BpfConnectionInfoT) *kafkaMember {
	if m, found := g.pending[conn]; found {
		return m
	}
	if g.size() >= maxMembersPerGroup {
		return nil
	}
	m := newKafkaMember()
	g.pending[conn] = m
	return m
}

// dropExpired forgets the members, named or pending, no request renewed before now.
func (g *kafkaMembership) dropExpired(now time.Time) {
	for id, m := range g.members {
		if !m.expires.After(now) {
			delete(g.members, id)
		}
	}
	for conn, m := range g.pending {
		if !m.expires.After(now) {
			delete(g.pending, conn)
		}
	}
}

// forEachMember calls fn for every member of the group, named or pending.
func (g *kafkaMembership) forEachMember(fn func(*kafkaMember)) {
	for _, m := range g.members {
		fn(m)
	}
	for _, m := range g.pending {
		fn(m)
	}
}

// subscribed reports whether any member of the group subscribes to topic.
func (g *kafkaMembership) subscribed(topic string) bool {
	found := false
	g.forEachMember(func(m *kafkaMember) {
		if _, ok := m.topics[topic]; ok {
			found = true
		}
	})
	return found
}

// kafkaProcessGroups is the membership state of one process, by group id.
type kafkaProcessGroups struct {
	groups map[string]*kafkaMembership
	// since is when the first group request of the process was seen. It lives with the
	// entry: a process that closes its last consumer and opens a new one within the ttl is
	// not warmed up again, but a run that starts after the entry expired is, because the
	// first requests of its groups may have gone unseen (a recycled pid before OBI
	// discovers it) and the fallback to the single known group would then be unguarded.
	since time.Time
}

// membership returns the state of group, creating it unless the process already holds
// maxGroupsPerProcess memberships (nil then).
func (p *kafkaProcessGroups) membership(group string) *kafkaMembership {
	g, found := p.groups[group]
	if found {
		return g
	}
	if len(p.groups) >= maxGroupsPerProcess {
		return nil
	}
	g = &kafkaMembership{members: map[string]*kafkaMember{}, pending: map[BpfConnectionInfoT]*kafkaMember{}}
	p.groups[group] = g
	return g
}

// dropExpired forgets the members no request renewed before now, and the groups left
// without members.
func (p *kafkaProcessGroups) dropExpired(now time.Time) {
	for group, g := range p.groups {
		g.dropExpired(now)
		if g.size() == 0 {
			delete(p.groups, group)
		}
	}
}

func (p *kafkaProcessGroups) topicBudget() int {
	kept := 0
	for _, g := range p.groups {
		g.forEachMember(func(m *kafkaMember) { kept += len(m.topics) })
	}
	return maxTopicsPerProcess - kept
}

// consumerGroup returns the only consumer group the process is a member of, "" when
// there is none or more than one.
func (p *kafkaProcessGroups) consumerGroup() string {
	single := ""
	for group, g := range p.groups {
		if g.foreign {
			continue
		}
		if single != "" {
			return ""
		}
		single = group
	}
	return single
}

// topicGroup returns the consumer group whose subscription holds topic. subscribed is
// false when no group does; group is "" when more than one does.
func (p *kafkaProcessGroups) topicGroup(topic string) (group string, subscribed bool) {
	for candidate, g := range p.groups {
		if g.foreign || !g.subscribed(topic) {
			continue
		}
		if subscribed {
			return "", true
		}
		group, subscribed = candidate, true
	}
	return group, subscribed
}

// KafkaConsumerGroups remembers, per process, the consumer groups it is a member of, the
// members it hosts in each and the subscription of every member. Membership is learned
// from the requests only a member sends (JoinGroup, SyncGroup, Heartbeat,
// ConsumerGroupHeartbeat) and forgotten when the member leaves. OffsetCommit and
// OffsetFetch name a group without proving membership (the admin client sends them for
// any group), so they only add topics to a member already known. A Fetch is attributed
// to the one group subscribed to its topic, else to the one consumer group the process
// is a member of: KIP-227 session fetches carry no topic, a topic UUID may not be
// resolved yet, and Heartbeat and SyncGroup carry no topics at all.
//
// Each member expires ttl after the last request asserting it; a Fetch lookup never
// extends it. A recycled pid inherits the previous process' memberships for at most
// ttl, and its own heartbeats renew only its own members; it also inherits the time the
// previous process was first seen, and so skips the warm-up. The LRU ttl on the whole
// entry reclaims processes that stopped sending group requests.
type KafkaConsumerGroups struct {
	lru *expirable.LRU[KafkaProcess, *kafkaProcessGroups]
	// ttl is how long a member outlives the last request asserting it, which makes it
	// the longest heartbeat interval the cache supports: a member heartbeating less often
	// expires in between, and its group's Fetches can then go to another group of the
	// process.
	ttl time.Duration
	// settle is how long a process must have been observed before any Fetch is attributed
	// to a group. OBI may attach after the consumers joined, and then learns each group
	// only from its next heartbeat: until every group of the process has sent one,
	// neither the single known group nor the one known subscriber of a topic proves that
	// no other group consumes it. Kafka bounds no heartbeat interval, so the window is the
	// ttl, the longest one the cache supports anyway.
	settle time.Duration
	now    func() time.Time
}

func NewKafkaConsumerGroups(size int, ttl time.Duration) *KafkaConsumerGroups {
	return &KafkaConsumerGroups{
		lru:    expirable.NewLRU[KafkaProcess, *kafkaProcessGroups](size, nil, ttl),
		ttl:    ttl,
		settle: ttl,
		now:    time.Now,
	}
}

// memberships returns proc's state with the expired memberships dropped, nil when the
// process is unknown. A state without memberships is kept, with its first-seen time,
// until the LRU's ttl reclaims it.
func (g *KafkaConsumerGroups) memberships(proc KafkaProcess) *kafkaProcessGroups {
	state, found := g.lru.Get(proc)
	if !found {
		return nil
	}
	state.dropExpired(g.now())
	return state
}

// Join records that req's member, living in proc and sending on conn, is a member of
// req's group; a request without a member id is the pending member of conn, see
// kafkaMembership.pending. A complete subscription (req.Subscription) replaces the topics
// known for that member, so a rebalance with a changed subscription drops the old
// topics; anything else adds to them. Topics referenced by UUID are resolved through
// kafkaTopicUUIDToName and skipped when unknown.
func (g *KafkaConsumerGroups) Join(proc KafkaProcess, conn BpfConnectionInfoT, req *kafkaparser.GroupRequest, kafkaTopicUUIDToName *simplelru.LRU[kafkaparser.UUID, string]) {
	if g == nil {
		return
	}
	state := g.memberships(proc)
	if state == nil {
		state = &kafkaProcessGroups{groups: map[string]*kafkaMembership{}, since: g.now()}
	}
	group := state.membership(req.GroupID)
	if group == nil {
		return
	}
	sortConnectionInfo(&conn)
	m := group.member(req.MemberID, conn)
	if m == nil {
		return
	}
	m.expires = g.now().Add(g.ttl)
	switch {
	case group.foreign || (req.ProtocolType != "" && req.ProtocolType != kafkaparser.ConsumerProtocolType):
		group.foreign = true
		group.forEachMember(func(m *kafkaMember) {
			m.topics = nil // whatever was added while the group passed for a consumer group is dead weight
		})
	case req.Subscription:
		m.topics = map[string]struct{}{}
		m.addTopics(req.Topics, kafkaTopicUUIDToName, state.topicBudget())
	default:
		m.addTopics(req.Topics, kafkaTopicUUIDToName, state.topicBudget())
	}
	g.lru.Add(proc, state)
}

// Leave forgets the given members of group in proc (LeaveGroup, or a
// ConsumerGroupHeartbeat with a negative member epoch), the pending member of conn, and
// the group itself once no member, named or pending, is left. A member that leaves
// before OBI saw a request carrying its id is still the pending member of the
// connection its leave arrives on. A LeaveGroup naming members proc does not host, as
// the admin client sends to remove members from any group, changes nothing: it arrives
// on the admin client's own connection, which holds no pending member.
func (g *KafkaConsumerGroups) Leave(proc KafkaProcess, conn BpfConnectionInfoT, group string, members []string) {
	if g == nil {
		return
	}
	state := g.memberships(proc)
	if state == nil {
		return
	}
	membership, member := state.groups[group]
	if !member {
		return
	}
	for _, id := range members {
		delete(membership.members, id)
	}
	sortConnectionInfo(&conn)
	delete(membership.pending, conn)
	if membership.size() > 0 {
		return
	}
	delete(state.groups, group)
}

// Enrich adds the topics named by an OffsetCommit or OffsetFetch to the subscription of
// req's member in proc; the request is ignored when proc does not host that member of
// that group (OffsetFetch before v9 names no member). It does not renew the membership:
// these requests are no evidence of it (see Join).
func (g *KafkaConsumerGroups) Enrich(proc KafkaProcess, req *kafkaparser.GroupRequest, kafkaTopicUUIDToName *simplelru.LRU[kafkaparser.UUID, string]) {
	if g == nil {
		return
	}
	state := g.memberships(proc)
	if state == nil {
		return
	}
	group, member := state.groups[req.GroupID]
	if !member || group.foreign {
		return
	}
	m, found := group.members[req.MemberID]
	if !found {
		return
	}
	m.addTopics(req.Topics, kafkaTopicUUIDToName, state.topicBudget())
}

// Lookup returns the group consuming topic in proc: the one group subscribed to it,
// or, when no subscription names it (unknown topic, Heartbeat only after a mid-stream
// attach, JoinGroup cut by the kernel buffer, list cut by maxGroupTopics or the topic
// caps), the single consumer group the process is a member of. Empty when several
// groups qualify or none does, and before the process has been observed for settle.
func (g *KafkaConsumerGroups) Lookup(proc KafkaProcess, topic string) string {
	if g == nil {
		return ""
	}
	state := g.memberships(proc)
	if state == nil {
		return ""
	}
	if g.now().Before(state.since.Add(g.settle)) {
		return ""
	}
	if group, subscribed := state.topicGroup(topic); subscribed {
		return group
	}
	return state.consumerGroup()
}

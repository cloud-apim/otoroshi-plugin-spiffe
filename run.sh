git clone --single-branch --branch v1.9.0 https://github.com/spiffe/spire.git
cd spire
go build ./cmd/spire-server
go build ./cmd/spire-agent
mkdir bin
mv spire-server spire-agent bin
bin/spire-server run -config conf/server/server.conf &
sleep 5
bin/spire-server healthcheck
bin/spire-server token generate -spiffeID spiffe://example.org/myagent
TOKEN=$(bin/spire-server token generate -spiffeID spiffe://example.org/myagent -output json | jq -r '.value')
bin/spire-agent run -config conf/agent/agent.conf -joinToken "$TOKEN" &
sleep 5
bin/spire-agent healthcheck
bin/spire-server entry create -parentID spiffe://example.org/myagent -spiffeID spiffe://example.org/myservice -selector unix:uid:$(id -u)
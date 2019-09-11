// Copyright 2018 CNI authors
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

// This is a "meta-plugin". It reads in its own netconf, combines it with
// the data from yonghui generated subnet file and then invokes a plugin
// like bridge or ipvlan to do the real work.

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/containernetworking/cni/pkg/invoke"
	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/types"
	"github.com/containernetworking/plugins/plugins/ipam/host-local/backend/allocator"
	"github.com/coreos/flannel/pkg/ip"
	"net"
	"os"
)

func doCmdAdd(args *skel.CmdArgs, n *NetConf, fenv *subnetEnv) error {
	n.Delegate["name"] = n.Name

	if !hasKey(n.Delegate, "type") {
		n.Delegate["type"] = "bridge"
	}

	if !hasKey(n.Delegate, "ipMasq") {
		// if yonghui is not doing ipmasq, we should
		ipmasq := !*fenv.ipmasq
		n.Delegate["ipMasq"] = ipmasq
	}

	if !hasKey(n.Delegate, "mtu") {
		mtu := fenv.mtu
		n.Delegate["mtu"] = mtu
	}

	if n.Delegate["type"].(string) == "bridge" {
		if !hasKey(n.Delegate, "isGateway") {
			n.Delegate["isGateway"] = true
		}
	}
	if n.CNIVersion != "" {
		n.Delegate["cniVersion"] = n.CNIVersion
	}

	defaultNet := &net.IPNet{
		IP:   net.IPv4zero,
		Mask: net.IPMask(net.IPv4zero),
	}

	_, gw, err := getIpRangeByCIDR(fenv.nw.String())
	if err != nil {
		panic(err)
	}

	minIp, maxIp, err := getIpRangeWithoutGwByCIDR(fenv.sn.String(), gw)
	if err != nil {
		panic(err)
	}

	// cluster ip range
	_, clusterIpn, err := net.ParseCIDR("10.96.0.1/12")
	if err != nil {
		panic(err)
	}

	n.Delegate["ipam"] = map[string]interface{}{
		"type": "host-local",
		"ranges": [][]allocator.Range{
			{
				{
					RangeStart: net.ParseIP(minIp),
					RangeEnd:   net.ParseIP(maxIp),
					Subnet:     types.IPNet(*fenv.nw),
					Gateway:    net.ParseIP(gw),
				},
			},
		},
		"routes": []types.Route{
			// cluster ip
			{
				Dst: *clusterIpn,
				GW:  (ip.FromIP(fenv.sn.IP) + 1).ToIP(),
			},
			// local network
			{
				Dst: *fenv.nw,
				GW:  net.ParseIP(gw),
			},
			// default gw
			{
				Dst: *defaultNet,
				GW:  net.ParseIP(gw),
			},
			//{
			//	Dst: *fenv.nw,
			//},
		},
	}

	return delegateAdd(args.ContainerID, n.DataDir, n.Delegate)
}

func doCmdDel(args *skel.CmdArgs, n *NetConf) error {
	netconfBytes, err := consumeScratchNetConf(args.ContainerID, n.DataDir)
	if err != nil {
		if os.IsNotExist(err) {
			// Per spec should ignore error if resources are missing / already removed
			return nil
		}
		return err
	}

	nc := &types.NetConf{}
	if err = json.Unmarshal(netconfBytes, nc); err != nil {
		return fmt.Errorf("failed to parse netconf: %v", err)
	}

	return invoke.DelegateDel(context.TODO(), nc.Type, netconfBytes, nil)
}

func getIpRangeByCIDR(cidr string) (string, string, error) {
	ipc, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return "", "", err
	}

	var ips []string
	for i := ipc.Mask(ipNet.Mask); ipNet.Contains(i); inc(i) {
		ips = append(ips, i.String())
	}

	return ips[1], ips[len(ips)-2], nil

	//minIp := (ip.FromIP(ipc) + 1).String()
	//maxIp := (ip.FromIP(ipOrMask(ipc, ipNet.Mask)) - 1).String()
	//
	//return minIp, maxIp, nil
}

func getIpRangeWithoutGwByCIDR(cidr, gw string) (string, string, error) {
	ipc, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return "", "", err
	}

	var ips []string
	for inst := ipc.Mask(ipNet.Mask); ipNet.Contains(inst); inc(inst) {
		ips = append(ips, inst.String())
	}

	// skip gateway ip
	if gw == ips[len(ips)-2] {
		return ips[1], ips[len(ips)-3], nil
	}
	// remove network address and broadcast address
	return ips[1], ips[len(ips)-2], nil

	//minIp := (ip.FromIP(ipc) + 1).String()
	//maxIp := (ip.FromIP(ipOrMask(ipc, ipNet.Mask)) - 1).String()
	//
	//// skip gateway ip
	//if gw == maxIp {
	//	return minIp, (ip.FromIP(ipOrMask(ipc, ipNet.Mask)) - 2).String(), nil
	//}
	//
	//return minIp, maxIp, nil
}

//func ipOrMask(ip net.IP, mask net.IPMask) net.IP {
//	n := len(ip)
//	if n != len(mask) {
//		return nil
//	}
//	out := make(net.IP, n)
//	for i := 0; i < n; i++ {
//		out[i] = ip[i] | mask[i]
//	}
//	return out
//}

func inc(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

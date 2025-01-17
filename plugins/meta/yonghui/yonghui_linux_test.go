// Copyright 2015 CNI authors
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
package main

import (
	"fmt"
	"io/ioutil"
	"os"
	"testing"

	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/types/current"
	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/containernetworking/plugins/pkg/testutils"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

func TestGetIpRangeByCIDR(t *testing.T){
	min, max, err := getIpRangeByCIDR("192.168.0.0/24")
	if err != nil {
		t.Errorf("err:%v", err.Error())
	}

	fmt.Printf("min:%v, max:%v", min, max)
}

var _ = Describe("Yonghui", func() {
	var (
		originalNS ns.NetNS
		input      string
		subnetFile string
		dataDir    string
	)

	BeforeEach(func() {
		var err error
		originalNS, err = testutils.NewNS()
		Expect(err).NotTo(HaveOccurred())
	})

	AfterEach(func() {
		Expect(originalNS.Close()).To(Succeed())
	})

	const inputTemplate = `
{
  "name": "cni-yonghui",
  "type": "yonghui",
	"subnetFile": "%s",
	"dataDir": "%s"
}`

	const flannelSubnetEnv = `
FLANNEL_NETWORK=10.1.0.0/16
FLANNEL_SUBNET=10.1.17.1/24
FLANNEL_MTU=1472
FLANNEL_IPMASQ=true
`

	var writeSubnetEnv = func(contents string) string {
		file, err := ioutil.TempFile("", "subnet.env")
		Expect(err).NotTo(HaveOccurred())
		_, err = file.WriteString(contents)
		Expect(err).NotTo(HaveOccurred())
		return file.Name()
	}

	BeforeEach(func() {
		var err error
		// yonghui subnet.env
		subnetFile = writeSubnetEnv(flannelSubnetEnv)

		// yonghui state dir
		dataDir, err = ioutil.TempDir("", "dataDir")
		Expect(err).NotTo(HaveOccurred())
		input = fmt.Sprintf(inputTemplate, subnetFile, dataDir)
	})

	AfterEach(func() {
		os.Remove(subnetFile)
		os.Remove(dataDir)
	})

	Describe("CNI lifecycle", func() {
		It("uses dataDir for storing network configuration", func() {
			const IFNAME = "eth0"

			targetNs, err := testutils.NewNS()
			Expect(err).NotTo(HaveOccurred())
			defer targetNs.Close()

			args := &skel.CmdArgs{
				ContainerID: "some-container-id",
				Netns:       targetNs.Path(),
				IfName:      IFNAME,
				StdinData:   []byte(input),
			}

			err = originalNS.Do(func(ns.NetNS) error {
				defer GinkgoRecover()

				By("calling ADD")
				resI, _, err := testutils.CmdAddWithArgs(args, func() error {
					return cmdAdd(args)
				})
				Expect(err).NotTo(HaveOccurred())

				By("check that plugin writes to net config to dataDir")
				path := fmt.Sprintf("%s/%s", dataDir, "some-container-id")
				Expect(path).Should(BeAnExistingFile())

				netConfBytes, err := ioutil.ReadFile(path)
				Expect(err).NotTo(HaveOccurred())
				expected := `{
   "ipMasq" : false,
   "ipam" : {
      "routes" : [
         {
            "dst" : "10.1.0.0/16"
         }
      ],
      "subnet" : "10.1.17.0/24",
      "type" : "host-local"
   },
   "isGateway": true,
   "mtu" : 1472,
   "name" : "cni-yonghui",
   "type" : "bridge"
}
`
				Expect(netConfBytes).Should(MatchJSON(expected))

				result, err := current.NewResultFromResult(resI)
				Expect(err).NotTo(HaveOccurred())
				Expect(result.IPs).To(HaveLen(1))

				By("calling DEL")
				err = testutils.CmdDelWithArgs(args, func() error {
					return cmdDel(args)
				})
				Expect(err).NotTo(HaveOccurred())

				By("check that plugin removes net config from state dir")
				Expect(path).ShouldNot(BeAnExistingFile())

				By("calling DEL again")
				err = testutils.CmdDelWithArgs(args, func() error {
					return cmdDel(args)
				})
				By("check that plugin does not fail due to missing net config")
				Expect(err).NotTo(HaveOccurred())

				return nil
			})
			Expect(err).NotTo(HaveOccurred())
		})
	})

	Describe("loadFlannelNetConf", func() {
		Context("when subnetFile and dataDir are specified", func() {
			It("loads yonghui network config", func() {
				conf, err := loadFlannelNetConf([]byte(input))
				Expect(err).ShouldNot(HaveOccurred())
				Expect(conf.Name).To(Equal("cni-yonghui"))
				Expect(conf.Type).To(Equal("yonghui"))
				Expect(conf.SubnetFile).To(Equal(subnetFile))
				Expect(conf.DataDir).To(Equal(dataDir))
			})
		})

		Context("when defaulting subnetFile and dataDir", func() {
			BeforeEach(func() {
				input = `{
"name": "cni-yonghui",
"type": "yonghui"
}`
			})

			It("loads yonghui network config with defaults", func() {
				conf, err := loadFlannelNetConf([]byte(input))
				Expect(err).ShouldNot(HaveOccurred())
				Expect(conf.Name).To(Equal("cni-yonghui"))
				Expect(conf.Type).To(Equal("yonghui"))
				Expect(conf.SubnetFile).To(Equal(defaultSubnetFile))
				Expect(conf.DataDir).To(Equal(defaultDataDir))
			})
		})

		Describe("loadFlannelSubnetEnv", func() {
			Context("when yonghui subnet env is valid", func() {
				It("loads yonghui subnet config", func() {
					conf, err := loadFlannelSubnetEnv(subnetFile)
					Expect(err).ShouldNot(HaveOccurred())
					Expect(conf.nw.String()).To(Equal("10.1.0.0/16"))
					Expect(conf.sn.String()).To(Equal("10.1.17.0/24"))
					var mtu uint = 1472
					Expect(*conf.mtu).To(Equal(mtu))
					Expect(*conf.ipmasq).To(BeTrue())
				})
			})

			Context("when yonghui subnet env is invalid", func() {
				BeforeEach(func() {
					subnetFile = writeSubnetEnv("foo=bar")
				})
				It("returns an error", func() {
					_, err := loadFlannelSubnetEnv(subnetFile)
					Expect(err).To(MatchError(ContainSubstring("missing FLANNEL_NETWORK, FLANNEL_SUBNET, FLANNEL_MTU, FLANNEL_IPMASQ")))
				})
			})
		})
	})
})

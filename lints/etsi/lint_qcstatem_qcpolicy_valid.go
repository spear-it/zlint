/*
 * ZLint Copyright 2020 Regents of the University of Michigan
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
 * implied. See the License for the specific language governing
 * permissions and limitations under the License.
 */

/************************************************
EN 319 411-2 v2.2.2 (2018-04): GEN-6.6.1-05
Scope: Subscriber
> The certificate shall include at least one of the following policy identifier:
> - [QCP-n]: 0.4.0.194112.1.0
> - [QCP-l]: 0.4.0.194112.1.1
> - [QCP-n-qscd]: 0.4.0.194112.1.2
> - [QCP-l-qscd]: 0.4.0.194112.1.3
> - [QCP-w]: 0.4.0.194112.1.4
************************************************/

package etsi

import (
	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zlint/lint"
	"github.com/zmap/zlint/util"
)

type qcStatemQcPolicyValid struct{}

func (l *qcStatemQcPolicyValid) Initialize() error {
	return nil
}

func (l *qcStatemQcPolicyValid) CheckApplies(c *x509.Certificate) bool {
	if !util.IsExtInCert(c, util.QcStateOid) {
		return false
	}
	if !util.IsCACert(c) && util.IsAnyEtsiQcStatementPresent(util.GetExtFromCert(c, util.QcStateOid).Value) {
		return true
	}
	return false
}

func (l *qcStatemQcPolicyValid) Execute(c *x509.Certificate) *lint.LintResult {

	for _, policyId := range c.PolicyIdentifiers {
		switch {
		case policyId.Equal(util.IdEtsiQcsPidNatural),
			policyId.Equal(util.IdEtsiQcsPidLegal),
			policyId.Equal(util.IdEtsiQcsPidNaturalQscd),
			policyId.Equal(util.IdEtsiQcsPidLegalQscd),
			policyId.Equal(util.IdEtsiQcsPidWeb):
			return &lint.LintResult{Status: lint.Pass}
		}
	}
	return &lint.LintResult{Status: lint.Error, Details: "missing mandatory policy identifier"}

}

func init() {
	lint.RegisterLint(&lint.Lint{
		Name:          "e_qcstatem_qcpolicy_valid",
		Description:   "The certificate shall include at least one of [QCP-n, QCP-l, QCP-n-qscd, QCP-l-qscd, QCP-w] policy identifiers",
		Citation:      "ETSI EN 319 411-2 V2.2.2 (2018-04) / Section GEN-6.6.1-05",
		Source:        lint.EtsiEsi,
		EffectiveDate: util.EtsiEn319_411_2_V2_2_2_Date,
		Lint:          &qcStatemQcPolicyValid{},
	})
}

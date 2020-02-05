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

/**************************************************
EN 319 411-2 v2.2.2 (2018-04): GEN-6.6.1-03
Scope: Subscriber
> [QCP-n-qscd] and [QCP-l-qscd]: The certificate
> shall include Statement for QSCD
> (esi4-qcStatement-4) defined in ETSI EN 319 412-5
**************************************************/

package etsi

import (
	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zlint/lint"
	"github.com/zmap/zlint/util"
)

type qcStatemQscdValid struct{}

func (l *qcStatemQscdValid) Initialize() error {
	return nil
}

func (l *qcStatemQscdValid) CheckApplies(c *x509.Certificate) bool {
	if !util.IsExtInCert(c, util.QcStateOid) {
		return false
	}
	if !util.IsCACert(c) && util.IsAnyEtsiQcStatementPresent(util.GetExtFromCert(c, util.QcStateOid).Value) {
		for _, policyId := range c.PolicyIdentifiers {
			if policyId.Equal(util.IdEtsiQcsPidNaturalQscd) || policyId.Equal(util.IdEtsiQcsPidLegalQscd) {
				return true
			}
		}
	}
	return false
}

func (l *qcStatemQscdValid) Execute(c *x509.Certificate) *lint.LintResult {

	ext := util.GetExtFromCert(c, util.QcStateOid)

	if util.ParseQcStatem(ext.Value, util.IdEtsiQcsQcSSCD).IsPresent() {
		return &lint.LintResult{Status: lint.Pass}
	} else {
		return &lint.LintResult{Status: lint.Error, Details: "missing the qcStatement for QSCD"}
	}

}

func init() {
	lint.RegisterLint(&lint.Lint{
		Name:          "e_qcstatem_qscd_valid",
		Description:   "[QCP-n-qscd] and [QCP-l-qscd]: The certificate shall include the qcStatement for QSCD (esi4-qcStatement-4) defined in ETSI EN 319 412-5",
		Citation:      "ETSI EN 319 411-2 V2.2.2 (2018-04) / Section GEN-6.6.1-03",
		Source:        lint.EtsiEsi,
		EffectiveDate: util.EtsiEn319_411_2_V2_2_2_Date,
		Lint:          &qcStatemQscdValid{},
	})
}

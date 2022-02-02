//
// Author:: Salim Afiune Maya (<afiune@lacework.net>)
// Copyright:: Copyright 2020, Lacework Inc.
// License:: Apache License, Version 2.0
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
//

package cmd

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/pkg/errors"
	"github.com/spf13/cobra"

	"github.com/lacework/go-sdk/api"
	"github.com/lacework/go-sdk/internal/array"
)

var (
	// complianceAzureListSubsCmd represents the list-subscriptions sub-command inside the azure command
	complianceAzureListSubsCmd = &cobra.Command{
		Use:     "list-subscriptions <tenant_id>",
		Aliases: []string{"list-subs"},
		Short:   "List subscriptions from tenant",
		Long: `List all Azure subscriptions from the provided Tenant ID.

Use the following command to list all Azure Tenants configured in your account:

    lacework compliance az list`,
		Args: cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			var (
				tenantID, _   = splitIDAndAlias(args[0])
				response, err = cli.LwApi.Compliance.ListAzureSubscriptions(tenantID)
			)
			if err != nil {
				return errors.Wrap(err, "unable to list azure subscriptions")
			}

			if len(response.Data) == 0 {
				return errors.New("no data found for the provided tenant")
			}

			// ALLY-431 Workaround to split the subscription ID and subscription Alias
			// ultimately, we need to fix this in the API response
			cliCompAzureSubscriptions := splitAzureSubscriptionsApiResponse(response.Data[0])

			if cli.JSONOutput() {
				return cli.OutputJSON(cliCompAzureSubscriptions)
			}

			rows := [][]string{}
			for _, subscription := range cliCompAzureSubscriptions.Subscriptions {
				rows = append(rows, []string{subscription.ID, subscription.Alias})
			}

			cli.OutputHuman(renderSimpleTable(
				[]string{"Subscription ID", "Subscription Alias"}, rows),
			)
			return nil
		},
	}

	// complianceAzureListTenantsCmd represents the list-tenants sub-command inside the azure command
	complianceAzureListTenantsCmd = &cobra.Command{
		Use:     "list",
		Aliases: []string{"list-tenants", "ls"},
		Short:   "List Azure tenants and subscriptions",
		Long:    `List all Azure tenants and subscriptions configured in your account.`,
		Args:    cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			cli.StartProgress("Fetching list of configured Azure tenants...")
			azureIntegrations, err := cli.LwApi.Integrations.ListAzureCfg()
			cli.StopProgress()
			if err != nil {
				return errors.Wrap(err, "unable to get azure integrations")
			}

			return cliListTenantsAndSubscriptions(&azureIntegrations)
		},
	}

	// complianceAzureGetReportCmd represents the get-report sub-command inside the azure command
	complianceAzureGetReportCmd = &cobra.Command{
		Use:     "get-report <tenant_id> <subscriptions_id>",
		Aliases: []string{"get"},
		PreRunE: func(_ *cobra.Command, _ []string) error {
			if compCmdState.Csv {
				cli.EnableCSVOutput()
			}

			switch compCmdState.Type {
			case "CIS", "SOC", "PCI":
				compCmdState.Type = fmt.Sprintf("AZURE_%s", compCmdState.Type)
				return nil
			case "AZURE_CIS", "AZURE_SOC", "AZURE_PCI":
				return nil
			default:
				return errors.New("supported report types are: CIS, SOC, or PCI")
			}
		},
		Short: "Get the latest Azure compliance report",
		Long: `Get the latest Azure compliance assessment report, these reports run on a regular schedule,
typically once a day. The available report formats are human-readable (default), json and pdf.

To run an ad-hoc compliance assessment use the command:

    lacework compliance azure run-assessment <tenant_id>
`,
		Args: cobra.ExactArgs(2),
		RunE: func(_ *cobra.Command, args []string) error {
			var (
				// clean tenantID and subscriptionID if they were provided
				// with an Alias in between parentheses
				tenantID, _       = splitIDAndAlias(args[0])
				subscriptionID, _ = splitIDAndAlias(args[1])
				config            = api.ComplianceAzureReportConfig{
					TenantID:       tenantID,
					SubscriptionID: subscriptionID,
					Type:           compCmdState.Type,
				}
			)

			if compCmdState.Pdf {
				pdfName := fmt.Sprintf(
					"%s_Report_%s_%s_%s_%s.pdf",
					config.Type,
					config.TenantID,
					config.SubscriptionID,
					cli.Account, time.Now().Format("20060102150405"),
				)

				cli.StartProgress("Downloading compliance report...")
				err := cli.LwApi.Compliance.DownloadAzureReportPDF(pdfName, config)
				cli.StopProgress()
				if err != nil {
					return errors.Wrap(err, "unable to get azure pdf compliance report")
				}

				cli.OutputHuman("The Azure compliance report was downloaded at '%s'\n", pdfName)
				return nil
			}

			if compCmdState.Severity != "" {
				if !array.ContainsStr(api.ValidEventSeverities, compCmdState.Severity) {
					return errors.Errorf("the severity %s is not valid, use one of %s",
						compCmdState.Severity, strings.Join(api.ValidEventSeverities, ", "),
					)
				}
			}
			if compCmdState.Status != "" {
				if !array.ContainsStr(api.ValidComplianceStatus, compCmdState.Status) {
					return errors.Errorf("the status %s is not valid, use one of %s",
						compCmdState.Status, strings.Join(api.ValidComplianceStatus, ", "),
					)
				}
			}

			var (
				report   api.ComplianceAzureReport
				cacheKey = fmt.Sprintf("compliance/azure/%s/%s/%s",
					config.TenantID, config.SubscriptionID, config.Type)
			)
			expired := cli.ReadCachedAsset(cacheKey, &report)
			if expired {
				cli.StartProgress("Getting compliance report...")
				response, err := cli.LwApi.Compliance.GetAzureReport(config)
				cli.StopProgress()
				if err != nil {
					return errors.Wrap(err, "unable to get azure compliance report")
				}

				if len(response.Data) == 0 {
					return errors.New("no data found in the report")
				}

				report = response.Data[0]

				cli.WriteAssetToCache(cacheKey, time.Now().Add(time.Minute*30), report)
			}

			filteredOutput := ""

			if complianceFiltersEnabled() {
				report.Recommendations, filteredOutput = filterRecommendations(report.Recommendations)
			}

			if cli.JSONOutput() {
				return cli.OutputJSON(report)
			}

			if cli.CSVOutput() {
				recommendations := complianceCSVReportRecommendationsTable(
					&complianceCSVReportDetails{
						AccountName:     report.SubscriptionName,
						AccountID:       report.SubscriptionID,
						TenantName:      report.TenantName,
						TenantID:        report.TenantID,
						ReportType:      report.ReportType,
						ReportTime:      report.ReportTime,
						Recommendations: report.Recommendations,
					},
				)

				return cli.OutputCSV(
					[]string{"Report_Type", "Report_Time", "Tenant",
						"Subscription", "Section", "ID", "Recommendation",
						"Status", "Severity", "Resource", "Region", "Reason"},
					recommendations,
				)
			}

			recommendations := complianceReportRecommendationsTable(report.Recommendations)
			cli.OutputHuman("\n")
			cli.OutputHuman(
				buildComplianceReportTable(
					complianceAzureReportDetailsTable(&report),
					complianceReportSummaryTable(report.Summary),
					recommendations,
					filteredOutput,
				),
			)
			return nil
		},
	}

	// complianceAzureRunAssessmentCmd represents the run-assessment sub-command inside the azure command
	complianceAzureRunAssessmentCmd = &cobra.Command{
		Use:     "run-assessment <tenant_id>",
		Aliases: []string{"run"},
		Short:   "Run a new Azure compliance assessment",
		Long:    `Run a compliance assessment of the provided Azure tenant.`,
		Args:    cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			response, err := cli.LwApi.Compliance.RunAzureReport(args[0])
			if err != nil {
				return errors.Wrap(err, "unable to run azure compliance assessment")
			}

			if cli.JSONOutput() {
				return cli.OutputJSON(response)
			}

			cli.OutputHuman("A new Azure compliance assessment has been initiated.\n")
			cli.OutputHuman("\n")
			cli.OutputHuman(
				renderSimpleTable(
					[]string{"INTEGRATION GUID", "TENANT ID"},
					[][]string{[]string{response.IntgGuid, args[0]}},
				),
			)
			return nil
		},
	}
)

func init() {
	// add sub-commands to the azure command
	complianceAzureCmd.AddCommand(complianceAzureListSubsCmd)
	complianceAzureCmd.AddCommand(complianceAzureListTenantsCmd)
	complianceAzureCmd.AddCommand(complianceAzureGetReportCmd)
	complianceAzureCmd.AddCommand(complianceAzureRunAssessmentCmd)

	complianceAzureGetReportCmd.Flags().BoolVar(&compCmdState.Details, "details", false,
		"increase details about the compliance report",
	)
	complianceAzureGetReportCmd.Flags().BoolVar(&compCmdState.Pdf, "pdf", false,
		"download report in PDF format",
	)

	// Output the report in CSV format
	complianceAzureGetReportCmd.Flags().BoolVar(&compCmdState.Csv, "csv", false,
		"output report in CSV format",
	)

	// Azure report types: AZURE_CIS, AZURE_SOC, or AZURE_PCI
	complianceAzureGetReportCmd.Flags().StringVar(&compCmdState.Type, "type", "CIS",
		"report type to display, supported types: CIS, SOC, or PCI",
	)

	complianceAzureGetReportCmd.Flags().StringSliceVar(&compCmdState.Category, "category", []string{},
		"filter report details by category (networking, storage, ...)",
	)

	complianceAzureGetReportCmd.Flags().StringSliceVar(&compCmdState.Service, "service", []string{},
		"filter report details by service (azure:ms:storage, azure:ms:sql, azure:ms:network, ...)",
	)

	complianceAzureGetReportCmd.Flags().StringVar(&compCmdState.Severity, "severity", "",
		fmt.Sprintf("filter report details by severity threshold (%s)",
			strings.Join(api.ValidEventSeverities, ", ")),
	)

	complianceAzureGetReportCmd.Flags().StringVar(&compCmdState.Status, "status", "",
		fmt.Sprintf("filter report details by status (%s)",
			strings.Join(api.ValidComplianceStatus, ", ")),
	)
}

func complianceAzureReportDetailsTable(report *api.ComplianceAzureReport) [][]string {
	return [][]string{
		[]string{"Report Type", report.ReportType},
		[]string{"Report Title", report.ReportTitle},
		[]string{"Tenant ID", report.TenantID},
		[]string{"Tenant Name", report.TenantName},
		[]string{"Subscription ID", report.SubscriptionID},
		[]string{"Subscription Name", report.SubscriptionName},
		[]string{"Report Time", report.ReportTime.UTC().Format(time.RFC3339)},
	}
}

// ALLY-431 Workaround to split the Subscription ID and Subscription Alias
// ultimately, we need to fix this in the API response
func splitAzureSubscriptionsApiResponse(azInfo api.CompAzureSubscriptions) cliComplianceAzureInfo {
	var (
		tenantID, tenantAlias = splitIDAndAlias(azInfo.Tenant)
		cliAzureInfo          = cliComplianceAzureInfo{
			Tenant:        cliComplianceIDAlias{tenantID, tenantAlias},
			Subscriptions: make([]cliComplianceIDAlias, 0),
		}
	)

	for _, subscription := range azInfo.Subscriptions {
		id, alias := splitIDAndAlias(subscription)
		cliAzureInfo.Subscriptions = append(cliAzureInfo.Subscriptions, cliComplianceIDAlias{id, alias})
	}

	return cliAzureInfo
}

type cliComplianceAzureInfo struct {
	Tenant        cliComplianceIDAlias   `json:"tenant"`
	Subscriptions []cliComplianceIDAlias `json:"subscriptions"`
}

func cliListTenantsAndSubscriptions(azureIntegrations *api.AzureIntegrationsResponse) error {
	jsonOut := struct {
		Subscriptions []azureSubscription `json:"azure_subscriptions"`
	}{Subscriptions: make([]azureSubscription, 0)}

	if azureIntegrations == nil || len(azureIntegrations.Data) == 0 {
		if cli.JSONOutput() {
			return cli.OutputJSON(jsonOut)
		}

		msg := `There are no Azure Tenants configured in your account.

Get started by integrating your Azure Tenants to analyze configuration compliance using the command:

    lacework integration create

If you prefer to configure the integration via the WebUI, log in to your account at:

    https://%s.lacework.net

Then navigate to Settings > Integrations > Cloud Accounts.
`
		cli.OutputHuman(fmt.Sprintf(msg, cli.Account))
		return nil
	}

	if cli.JSONOutput() {
		jsonOut.Subscriptions = extractAzureSubscriptions(azureIntegrations)
		return cli.OutputJSON(jsonOut)
	}

	var rows [][]string
	for _, az := range extractAzureSubscriptions(azureIntegrations) {
		rows = append(rows, []string{az.TenantID, az.SubscriptionID, az.Status})
	}

	cli.OutputHuman(renderSimpleTable([]string{"Azure Tenant", "Azure Subscription", "Status"}, rows))
	return nil
}

type azureSubscription struct {
	TenantID       string `json:"tenant_id"`
	SubscriptionID string `json:"subscription_id"`
	Status         string `json:"status"`
}

func extractAzureSubscriptions(response *api.AzureIntegrationsResponse) []azureSubscription {
	var azureSubscriptions []azureSubscription

	if response == nil {
		return azureSubscriptions
	}

	for _, gcp := range response.Data {
		// fetch the subscription ids from tenant id
		azureSubscriptions = append(azureSubscriptions, getAzureSubscriptions(gcp.Data.TenantID, gcp.Status())...)
	}

	sort.Slice(azureSubscriptions, func(i, j int) bool {
		switch strings.Compare(azureSubscriptions[i].TenantID, azureSubscriptions[j].TenantID) {
		case -1:
			return true
		case 1:
			return false
		}
		return azureSubscriptions[i].SubscriptionID < azureSubscriptions[j].SubscriptionID
	})

	return azureSubscriptions
}

func getAzureSubscriptions(tenantID, status string) []azureSubscription {
	var subs []azureSubscription
	cli.StartProgress(fmt.Sprintf("Fetching subscriptions from tenant (%s)...", tenantID))
	subsResponse, err := cli.LwApi.Compliance.ListAzureSubscriptions(tenantID)
	cli.StopProgress()
	if err != nil {
		cli.Log.Warn("unable to list azure subscriptions", "tenant_id", tenantID, "error", err.Error())
		return subs
	}
	for _, subsRes := range subsResponse.Data {
		for _, subRes := range subsRes.Subscriptions {
			subscriptionID, _ := splitIDAndAlias(subRes)
			subs = append(subs, azureSubscription{
				TenantID:       tenantID,
				SubscriptionID: subscriptionID,
				Status:         status,
			})
		}
	}
	return subs
}
